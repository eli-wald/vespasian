// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdk

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/pkg/analyze"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// Compile-time interface satisfaction check.
var _ capability.Capability[capmodel.WebApplication] = (*Capability)(nil)

// crawlFunc is a package-level seam that tests can swap to avoid launching a
// real browser. Signature matches defaultCrawl; tests replace it with a stub.
var crawlFunc func(ctx context.Context, opts crawl.CrawlerOptions, target string) ([]crawl.ObservedRequest, error) = defaultCrawl

// Capability implements capability.Capability[capmodel.WebApplication] and
// exposes the vespasian crawl → classify → probe → generate pipeline through
// the standard capability-sdk interface.
type Capability struct{}

// Name returns the capability identifier.
func (c *Capability) Name() string { return "vespasian" }

// Description returns a human-readable summary.
func (c *Capability) Description() string {
	return "discovers API endpoints via headless browser crawling and generates OpenAPI / GraphQL SDL / WSDL specs"
}

// Input returns the zero value of the input type used for JSON unmarshalling.
func (c *Capability) Input() any { return capmodel.WebApplication{} }

// Full implements capability.PeriodicCapability — run a full scan every 5 days.
func (c *Capability) Full() time.Duration { return 5 * 24 * time.Hour }

// Timeout implements capability.TimeoutCapability — 30 minutes worst-case.
func (c *Capability) Timeout() int { return 30 }

// Parameters declares the configurable parameters for this capability.
func (c *Capability) Parameters() []capability.Parameter {
	return []capability.Parameter{
		capability.String("mode", "Operating mode: scan or crawl").WithDefault("scan").WithOptions("scan", "crawl"),
		capability.String("api_type", "API type: auto, rest, graphql, wsdl").WithDefault("auto").WithOptions("auto", "rest", "graphql", "wsdl"),
		capability.Int("timeout", "Total crawl duration in seconds").WithDefault("600"),
		capability.Int("max_pages", "Maximum pages to crawl").WithDefault("100"),
		capability.Int("depth", "Maximum crawl depth").WithDefault("3"),
		capability.String("scope", "Crawl scope: same-origin or same-domain").WithDefault("same-origin").WithOptions("same-origin", "same-domain"),
		capability.String("headers", "Comma-separated auth headers (e.g. Authorization: Bearer tok)"),
		capability.String("confidence", "Minimum classification confidence 0-1").WithDefault("0.5"),
		capability.Bool("probe", "Enable endpoint probing").WithDefault("true"),
	}
}

// Match validates the input before Invoke is called.
func (c *Capability) Match(_ capability.ExecutionContext, input capmodel.WebApplication) error {
	if input.PrimaryURL == "" {
		return fmt.Errorf("primary_url is required")
	}
	if !strings.HasPrefix(input.PrimaryURL, "http") {
		return fmt.Errorf("vespasian requires HTTP/HTTPS URL, got %q", input.PrimaryURL)
	}
	if !input.Seed {
		return fmt.Errorf("vespasian only runs on web application seeds")
	}
	return nil
}

// Invoke runs the pipeline (crawl, and optionally classify → probe → generate).
func (c *Capability) Invoke(ctx capability.ExecutionContext, input capmodel.WebApplication, output capability.Emitter) error {
	mode, _ := ctx.Parameters.GetString("mode")
	if mode == "" {
		mode = "scan"
	}

	opts, err := crawlOptsFromCtx(ctx)
	if err != nil {
		return err
	}

	start := time.Now()

	requests, err := crawlFunc(context.Background(), opts, input.PrimaryURL)
	if err != nil {
		return fmt.Errorf("vespasian: crawl failed: %w", err)
	}

	// Augment with static HTML form analysis (mirrors CLI pipeline).
	requests = append(requests, analyze.ExtractForms(requests)...)

	// Group requests by page URL and emit Webpage entries (filter static assets).
	parent := capmodel.WebApplication{PrimaryURL: input.PrimaryURL, Name: input.Name}
	emittedPages := emitWebpages(requests, parent, output)

	if mode == "crawl" {
		slog.Info("vespasian crawl completed",
			"target", input.PrimaryURL,
			"mode", "crawl",
			"duration_ms", time.Since(start).Milliseconds(),
			"crawled_pages", len(requests),
			"emitted_webpages", emittedPages,
		)
		return nil
	}

	hasSpec, apiType := c.runScan(ctx, requests, input, output)

	slog.Info("vespasian scan completed",
		"target", input.PrimaryURL,
		"mode", "scan",
		"duration_ms", time.Since(start).Milliseconds(),
		"crawled_pages", len(requests),
		"emitted_webpages", emittedPages,
		"has_spec", hasSpec,
		"api_type", apiType,
	)
	return nil
}

// runScan runs the classify → probe → generate phase and emits a WebApplication
// with the spec if one is produced. Returns (hasSpec, resolvedAPIType).
func (c *Capability) runScan(ctx capability.ExecutionContext, requests []crawl.ObservedRequest, input capmodel.WebApplication, output capability.Emitter) (bool, string) {
	if len(requests) == 0 {
		return false, "rest"
	}

	confidence := parseConfidence(ctx.Parameters)
	probeEnabled := parseProbeEnabled(ctx.Parameters)

	apiType, _ := ctx.Parameters.GetString("api_type")
	if apiType == "" || apiType == "auto" {
		apiType = detectAPIType(requests, confidence)
	}

	spec, err := classifyProbeGenerate(context.Background(), requests, apiType, confidence, probeEnabled)
	if err != nil {
		slog.Warn("vespasian: classify/generate failed", "target", input.PrimaryURL, "error", err)
		return false, apiType
	}

	if len(bytes.TrimSpace(spec)) == 0 {
		return false, apiType
	}

	webApp := input
	webApp.Spec = string(spec)
	webApp.SpecFormat = specFormatForType(apiType)
	_ = output.Emit(webApp) //nolint:errcheck // emitter errors are non-fatal; logged by host
	return true, apiType
}

// ---------------------------------------------------------------------------
// Crawl seam
// ---------------------------------------------------------------------------

func defaultCrawl(ctx context.Context, opts crawl.CrawlerOptions, target string) ([]crawl.ObservedRequest, error) {
	c := crawl.NewCrawler(opts)
	return c.Crawl(ctx, target)
}

// crawlOptsFromCtx extracts and validates crawl options from the execution context.
func crawlOptsFromCtx(ctx capability.ExecutionContext) (crawl.CrawlerOptions, error) {
	scope, _ := ctx.Parameters.GetString("scope")
	if scope == "" {
		scope = "same-origin"
	}
	if scope != "same-origin" && scope != "same-domain" {
		return crawl.CrawlerOptions{}, fmt.Errorf("vespasian: invalid scope %q, must be 'same-origin' or 'same-domain'", scope)
	}

	opts := crawl.CrawlerOptions{
		Timeout:  600 * time.Second,
		MaxPages: 100,
		Depth:    3,
		Scope:    scope,
		Headless: true,
	}
	if t, ok := ctx.Parameters.GetInt("timeout"); ok {
		opts.Timeout = time.Duration(t) * time.Second
	}
	if m, ok := ctx.Parameters.GetInt("max_pages"); ok {
		opts.MaxPages = m
	}
	if d, ok := ctx.Parameters.GetInt("depth"); ok {
		opts.Depth = d
	}
	if h, ok := ctx.Parameters.GetString("headers"); ok && h != "" {
		opts.Headers = parseHeaders(h)
	}
	return opts, nil
}

func parseConfidence(params capability.Parameters) float64 {
	cf, ok := params.GetString("confidence")
	if !ok || cf == "" {
		return 0.5
	}
	var v float64
	if _, err := fmt.Sscanf(cf, "%f", &v); err != nil {
		return 0.5
	}
	return v
}

func parseProbeEnabled(params capability.Parameters) bool {
	p, ok := params.GetBool("probe")
	if !ok {
		return true
	}
	return p
}

// ---------------------------------------------------------------------------
// Pipeline helpers (ported from cmd/vespasian/main.go)
// ---------------------------------------------------------------------------

// detectAPIType runs lightweight classification against all three API types and
// picks the winner. GraphQL wins when it has matches and at least as many as
// both others. WSDL wins when it has matches and at least as many as REST.
// Otherwise REST is returned.
func detectAPIType(requests []crawl.ObservedRequest, threshold float64) string {
	wsdlC := &classify.WSDLClassifier{}
	restC := &classify.RESTClassifier{}
	graphqlC := &classify.GraphQLClassifier{}

	var wsdlCount, restCount, graphqlCount int
	for _, req := range requests {
		if isAPI, conf := wsdlC.Classify(req); isAPI && conf >= threshold {
			wsdlCount++
		}
		if isAPI, conf := restC.Classify(req); isAPI && conf >= threshold {
			restCount++
		}
		if isAPI, conf := graphqlC.Classify(req); isAPI && conf >= threshold {
			graphqlCount++
		}
	}

	if graphqlCount > 0 && graphqlCount >= wsdlCount && graphqlCount >= restCount {
		return "graphql"
	}
	if wsdlCount > 0 && wsdlCount >= restCount {
		return "wsdl"
	}
	return "rest"
}

// classifyProbeGenerate runs the classify → probe → generate pipeline.
func classifyProbeGenerate(ctx context.Context, requests []crawl.ObservedRequest, apiType string, confidence float64, probeEnabled bool) ([]byte, error) {
	classifiers := classifiersForType(apiType)
	if classifiers == nil {
		return nil, fmt.Errorf("unsupported API type: %q", apiType)
	}

	classified := classify.Deduplicate(classify.RunClassifiers(classifiers, requests, confidence))

	if probeEnabled {
		cfg := probe.DefaultConfig()
		strategies := strategiesForType(apiType, cfg)
		enriched, probeErrs := probe.RunStrategies(ctx, strategies, classified)
		for _, e := range probeErrs {
			slog.Warn("vespasian: probe strategy failed", "error", e)
		}
		classified = enriched
	}

	gen, err := generate.Get(apiType)
	if err != nil {
		return nil, fmt.Errorf("vespasian: unsupported api type %q: %w", apiType, err)
	}
	return gen.Generate(classified)
}

func classifiersForType(apiType string) []classify.APIClassifier {
	switch apiType {
	case "rest":
		return []classify.APIClassifier{&classify.RESTClassifier{}}
	case "wsdl":
		return []classify.APIClassifier{&classify.WSDLClassifier{}}
	case "graphql":
		return []classify.APIClassifier{&classify.GraphQLClassifier{}}
	default:
		return nil
	}
}

func strategiesForType(apiType string, cfg probe.Config) []probe.ProbeStrategy {
	switch apiType {
	case "wsdl":
		return []probe.ProbeStrategy{probe.NewWSDLProbe(cfg)}
	case "graphql":
		return []probe.ProbeStrategy{probe.NewGraphQLProbe(cfg)}
	default:
		return []probe.ProbeStrategy{probe.NewOptionsProbe(cfg), probe.NewSchemaProbe(cfg)}
	}
}

func specFormatForType(apiType string) string {
	switch apiType {
	case "graphql":
		return capmodel.SpecFormatGraphQL
	case "wsdl":
		return capmodel.SpecFormatWSDL
	default:
		return capmodel.SpecFormatOpenAPI
	}
}

// ---------------------------------------------------------------------------
// Emit helpers
// ---------------------------------------------------------------------------

// emitWebpages groups requests by page URL, filters static assets, and emits
// one capmodel.Webpage per unique non-static URL. Returns the number emitted.
func emitWebpages(requests []crawl.ObservedRequest, parent capmodel.WebApplication, output capability.Emitter) int {
	byURL := make(map[string][]capmodel.WebpageRequest)
	var order []string
	for _, req := range requests {
		pageURL := req.URL
		if pageURL == "" {
			continue
		}
		if isStaticAssetURL(pageURL) {
			continue
		}
		if _, seen := byURL[pageURL]; !seen {
			order = append(order, pageURL)
		}
		byURL[pageURL] = append(byURL[pageURL], toWebpageRequest(req))
	}

	count := 0
	for _, u := range order {
		_ = output.Emit(capmodel.Webpage{ //nolint:errcheck // emitter errors are non-fatal; logged by host
			URL:      u,
			Requests: byURL[u],
			Parent:   parent,
		})
		count++
	}
	return count
}

// toWebpageRequest converts a crawl.ObservedRequest to capmodel.WebpageRequest,
// converting single-value headers to multi-value form.
func toWebpageRequest(req crawl.ObservedRequest) capmodel.WebpageRequest {
	wpReq := capmodel.WebpageRequest{
		RequestedURL: req.URL,
		Method:       req.Method,
		Headers:      toMultiValueHeaders(req.Headers),
		Body:         string(req.Body),
	}
	resp := req.Response
	if resp.StatusCode != 0 || len(resp.Body) > 0 || len(resp.Headers) > 0 {
		wpReq.Response = &capmodel.WebpageResponse{
			StatusCode: resp.StatusCode,
			Headers:    toMultiValueHeaders(resp.Headers),
			Body:       string(resp.Body),
		}
	}
	return wpReq
}

func toMultiValueHeaders(headers map[string]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for k, v := range headers {
		result[k] = []string{v}
	}
	return result
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// parseHeaders parses a comma-separated "Key: Value, K2: V2" string.
// Whitespace around keys and values is trimmed. Returns nil for empty input.
func parseHeaders(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	headers := make(map[string]string)
	for _, hdr := range strings.Split(raw, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(hdr), ":"); ok {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return headers
}

// isStaticAssetURL returns true when the URL path has a static-asset extension.
// Ported from guard/backend/pkg/lib/web/url.go.
func isStaticAssetURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(parsed.Path)
	for _, ext := range staticAssetExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

var staticAssetExtensions = []string{
	".css", ".js", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".webmanifest",
	".mp4", ".webm", ".mp3", ".ogg",
}
