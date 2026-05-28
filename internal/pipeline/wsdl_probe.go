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

package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	wsdlgen "github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// writeStatus writes a status message to w if w is non-nil. Used to forward
// optional progress output without forcing every call site to nil-check.
func writeStatus(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...) //nolint:errcheck,gosec // best-effort status output
}

// ProbeWSDLDocument attempts to fetch a WSDL document from targetURL?wsdl.
// Returns the raw WSDL bytes on success, or nil if the probe fails or the
// response is not a valid WSDL document. status is an optional io.Writer
// for progress messages; pass nil or io.Discard to suppress them.
func ProbeWSDLDocument(ctx context.Context, targetURL string, allowPrivate bool, status io.Writer) []byte {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		writeStatus(status, "wsdl discovery: invalid URL %q: %v\n", targetURL, err)
		return nil
	}
	parsedURL.RawQuery = "wsdl"
	wsdlURL := parsedURL.String()

	writeStatus(status, "wsdl discovery: probing %s\n", wsdlURL)

	if !allowPrivate {
		if err := probe.ValidateProbeURL(wsdlURL); err != nil {
			writeStatus(status, "wsdl discovery: skipping %s (SSRF protection: %v)\n", wsdlURL, err)
			return nil
		}
	}

	transport := &http.Transport{
		DialContext: probe.SSRFSafeDialContext,
	}
	if allowPrivate {
		transport = &http.Transport{}
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wsdlURL, nil)
	if err != nil {
		writeStatus(status, "wsdl discovery: failed to create request: %v\n", err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		writeStatus(status, "wsdl discovery: request failed: %v\n", err)
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck,gosec // best-effort close
	}()

	if resp.StatusCode >= 400 {
		writeStatus(status, "wsdl discovery: %s returned HTTP %d\n", wsdlURL, resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil
	}

	// Validate the response is actually a WSDL document.
	if _, parseErr := wsdlgen.ParseWSDL(body); parseErr != nil {
		writeStatus(status, "wsdl discovery: response is not valid WSDL: %v\n", parseErr)
		return nil
	}

	return body
}
