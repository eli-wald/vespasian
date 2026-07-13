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
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/analyze"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// seedGRPCHostEndpoints returns classified plus one synthetic grpc-typed
// ClassifiedRequest per distinct host (scheme://host[:port]) observed in
// requests that is not already represented among classified grpc endpoints.
// Hosts are deduped, sorted for deterministic output, and capped at maxHosts.
// The synthetic endpoints give the reflection and grpc-gateway probes targets
// even when classification never marked the (REST/JSON) gateway traffic grpc.
// SSRF protection is unaffected: seeding only constructs URLs; the probes still
// run URLValidator/Dialer.
func seedGRPCHostEndpoints(requests []crawl.ObservedRequest, classified []classify.ClassifiedRequest, maxHosts int) []classify.ClassifiedRequest {
	// Hosts already represented among classified grpc endpoints are not re-seeded.
	existing := map[string]bool{}
	for i := range classified {
		if classified[i].APIType != APITypeGRPC {
			continue
		}
		if host := grpcHostKey(classified[i].URL); host != "" {
			existing[host] = true
		}
	}

	seen := map[string]bool{}
	var hosts []string
	for _, req := range requests {
		host := grpcHostKey(req.URL)
		if host == "" || existing[host] || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}

	sort.Strings(hosts)
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	for _, host := range hosts {
		classified = append(classified, classify.ClassifiedRequest{
			ObservedRequest: crawl.ObservedRequest{URL: host},
			APIType:         APITypeGRPC,
		})
	}
	return classified
}

// grpcHostKey returns the scheme://host[:port] key for a request URL, or ""
// when the URL cannot be parsed or carries no host. The original scheme is
// preserved (empty→https); the probes themselves map grpc/grpcs↔http/https as
// needed.
//
// Note: pkg/probe.openAPIBaseURL performs a similar URL→scheme://host parse but
// intentionally maps grpc/grpcs→http/https (it fetches the gateway's HTTP
// document). This helper instead PRESERVES the original scheme. The
// scheme-handling difference is deliberate — they are not equivalent, do not
// unify them into one shared helper (Rule of Three not met).
func grpcHostKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.Host
}

// enrichGRPCFromBindings recovers gRPC services from gRPC-Web JS bundles in the
// full augmented capture and surfaces them with the lowest precedence in the
// reflection > gateway > bindings chain. Precedence is enforced at method
// granularity by the generator's per-FQN method union, not by dropping whole
// services here: a service only PARTIALLY covered by grpc-gateway (its
// transcodable unary methods) still contributes its bindings-only methods
// (e.g. client-streaming/bidi RPCs the gateway cannot transcode).
//
// Recovered services are split three ways by how their FQN is already covered:
//   - uncovered (by any technique): filled onto a bare grpc endpoint in place,
//     or appended when none exists (pure gRPC-Web SPA);
//   - covered ONLY by a name-only technique (grpc-gateway): appended on a
//     trailing endpoint — never filled onto a pre-existing endpoint — so the
//     gateway endpoint always precedes it and the generator's method union
//     keeps the gateway's method definitions while adding the bindings-only
//     ones;
//   - covered by reflection: dropped here (reflection is authoritative and its
//     real FileDescriptors are never grafted with synthetic method stubs); the
//     generator also drops reflected FQNs as a backstop.
//
// It never overwrites an endpoint that already carries usable descriptors
// (reflection or gateway).
//
// Bindings recovery reads JS bodies from the capture rather than the network,
// so it is not a ProbeStrategy: the classified/deduped endpoints handed to
// probes are API endpoints, not the JS bundles (which are filtered out before
// probing). Only the pipeline's request slice holds the full capture this
// needs.
func enrichGRPCFromBindings(requests []crawl.ObservedRequest, enriched []classify.ClassifiedRequest, status io.Writer) []classify.ClassifiedRequest {
	services := analyze.ExtractGRPCWebBindings(requests)
	if len(services) == 0 {
		return enriched
	}

	uncovered := filterUncoveredServices(services, enriched)
	nameOnlyExtra := nameOnlyCoveredServices(services, enriched)
	if len(uncovered) == 0 && len(nameOnlyExtra) == 0 {
		return enriched
	}

	writeStatus(status, "recovered %d service(s) from gRPC-Web bundles\n", len(uncovered)+len(nameOnlyExtra))

	// Store recovered service names only. Descriptor synthesis is centralized
	// in the generator. ReflectionEnabled is false: JS bindings are not a
	// reflection response.
	grpcSchema := func(svcs []classify.GRPCService) *classify.GRPCReflectionResult {
		return &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services:          svcs,
		}
	}

	// "Covered" for fill purposes means the endpoint already carries usable
	// descriptors or recovered service names (reflection or gateway).
	hasCoverage := func(s *classify.GRPCReflectionResult) bool {
		return s != nil && (len(s.FileDescriptors) > 0 || len(s.Services) > 0)
	}

	// Fill genuinely-new (uncovered) services onto every bare grpc endpoint in
	// place. An uncovered FQN appears on no existing endpoint, so filling it
	// cannot invert gateway > bindings precedence.
	attached := false
	if len(uncovered) > 0 {
		for i := range enriched {
			if enriched[i].APIType != APITypeGRPC {
				continue
			}
			if hasCoverage(enriched[i].GRPCSchema) {
				continue
			}
			enriched[i].GRPCSchema = grpcSchema(uncovered)
			attached = true
		}
	}

	// Build the trailing endpoint. name-only-covered services are always
	// appended (never filled) so their gateway endpoint precedes them and the
	// generator's method union keeps the gateway definitions. Uncovered
	// services ride along only when no bare endpoint accepted them.
	var trailing []classify.GRPCService
	if len(uncovered) > 0 && !attached {
		trailing = append(trailing, uncovered...)
	}
	trailing = append(trailing, nameOnlyExtra...)
	if len(trailing) > 0 {
		enriched = append(enriched, classify.ClassifiedRequest{
			APIType:    APITypeGRPC,
			GRPCSchema: grpcSchema(trailing),
		})
	}

	return enriched
}

// filterUncoveredServices returns the subset of services whose FQN is not
// already recovered (in GRPCSchema.Services) by any endpoint in enriched.
// Leading dots are stripped before comparison so ".pkg.S" and "pkg.S" match.
//
// Coverage is keyed on GRPCSchema.Services — the durable, per-FQN signal —
// rather than on FileDescriptors. This is deliberate and correct for both
// paths: the live reflection probe records each service in .Services via
// extractService (pkg/probe.runReflection), and imported captures persist
// .Services but NOT FileDescriptors (json:"-"), so .Services is the only signal
// that survives a capture round-trip. Precise per-FQN dedup of the rare
// reflection endpoint that carries FileDescriptors but an empty/partial
// .Services (e.g. the probe's descriptor budget was exhausted mid-enumeration,
// or one file declares several services) would require parsing the descriptor
// bytes — an expensive parseDescriptorSet we intentionally avoid here — and
// keying on len(FileDescriptors)>0 cannot recover per-FQN coverage without
// over-dropping legitimate bindings-only services. That rare case is not a bug:
// a bindings FQN already defined by reflection is carried through as a redundant
// trailing synthetic endpoint, and the generator's unionRecoveredServices →
// reflectedFQNs backstop (which DOES parse the merged FileDescriptors) drops it,
// so the emitted .proto is correct. See nameOnlyCoveredServices, which keys on
// the same .Services signal and only uses ReflectionEnabled || FileDescriptors>0
// to bucket an endpoint as reflection vs name-only (not for per-FQN coverage).
func filterUncoveredServices(services []classify.GRPCService, enriched []classify.ClassifiedRequest) []classify.GRPCService {
	covered := map[string]bool{}
	for i := range enriched {
		if s := enriched[i].GRPCSchema; s != nil {
			for _, svc := range s.Services {
				covered[strings.TrimPrefix(svc.Name, ".")] = true
			}
		}
	}
	filtered := services[:0:0]
	for _, svc := range services {
		if covered[strings.TrimPrefix(svc.Name, ".")] {
			continue
		}
		filtered = append(filtered, svc)
	}
	return filtered
}

// nameOnlyCoveredServices returns the subset of services whose FQN is already
// recovered by a NAME-ONLY endpoint (grpc-gateway: ReflectionEnabled=false and
// no FileDescriptors) but is NOT covered by reflection. These are carried — on
// a trailing endpoint — so the generator's per-method union can add the
// bindings-only methods (e.g. client-streaming/bidi RPCs grpc-gateway cannot
// transcode) to a service the gateway only partially covered, while the
// gateway's method definitions win.
//
// Reflection-covered FQNs are excluded: reflection is authoritative and its
// real FileDescriptors are never augmented with synthetic method stubs
// (invariant preserved here and again as a backstop in the generator's union).
// Leading dots are stripped before comparison so ".pkg.S" and "pkg.S" match.
func nameOnlyCoveredServices(services []classify.GRPCService, enriched []classify.ClassifiedRequest) []classify.GRPCService {
	reflectionFQNs := map[string]bool{}
	nameOnlyFQNs := map[string]bool{}
	for i := range enriched {
		s := enriched[i].GRPCSchema
		if s == nil {
			continue
		}
		reflected := s.ReflectionEnabled || len(s.FileDescriptors) > 0
		for _, svc := range s.Services {
			fqn := strings.TrimPrefix(svc.Name, ".")
			if reflected {
				reflectionFQNs[fqn] = true
			} else {
				nameOnlyFQNs[fqn] = true
			}
		}
	}

	extra := services[:0:0]
	for _, svc := range services {
		fqn := strings.TrimPrefix(svc.Name, ".")
		if reflectionFQNs[fqn] {
			continue
		}
		if nameOnlyFQNs[fqn] {
			extra = append(extra, svc)
		}
	}
	return extra
}
