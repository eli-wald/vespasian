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

package pipeline_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// PR #160 review TEST-001 (the blocker): end-to-end seed → gateway-probe →
// generate assembly.
//
// This proves the B2 headline path: a PURE-REST (grpc-gateway) capture, with
// reflection off, yields a non-empty .proto through the FULL
// ClassifyProbeGenerate pipeline, with the gateway swagger genuinely FETCHED
// over the network (not hand-built and injected into a GRPCSchema).
//
// The assembly exercised, in order:
//  1. classify.RunClassifiers(GRPCClassifier) — the capture below is plain
//     REST/JSON traffic, so it is NOT classified as APIType=="grpc".
//  2. seedGRPCHostEndpoints (internal/pipeline/grpc_enrich.go) — because step 1
//     produced zero grpc-typed endpoints, this seeds one synthetic grpc
//     endpoint for the request's host so the grpc probes have a target at all.
//  3. probe.RunStrategies → probe.NewGRPCGatewayProbe fetches the well-known
//     /swagger.json path from the seeded endpoint's host — a REAL HTTP request
//     to the httptest.Server below, not a hand-built GRPCSchema.
//  4. generate/grpc.Generate synthesizes a .proto from the recovered service
//     names.
//
// AllowPrivate=true is REQUIRED: the httptest.Server listens on loopback, and
// this also exercises the FIX-1 allow-private branch in
// ClassifyProbeGenerate (clones probe.DefaultTransport(), overrides only
// DialContext).
func TestClassifyProbeGenerate_GRPCGatewayE2E_PureRESTCaptureYieldsProto(t *testing.T) {
	// Reuse the same grpc-gateway swagger fixture the probe's own unit tests
	// use, rather than hand-rolling a document inline, so this test exercises
	// exactly the document shape the probe is proven to recognize.
	fixturePath := filepath.Join("..", "..", "pkg", "probe", "testdata", "grpc_gateway", "swagger.json")
	body, err := os.ReadFile(fixturePath) // #nosec G304 -- fixed local testdata fixture
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	// PURE-REST capture: a plain GET to a REST-shaped path. Method GET (not
	// POST) and the path does not match the /<pkg.Service>/<Method> gRPC path
	// shape, and there is no application/grpc content-type or grpc-status
	// trailer, so classify.GRPCClassifier scores this as NOT gRPC — this is
	// the "pure grpc-gateway REST traffic" case that seedGRPCHostEndpoints
	// must seed a synthetic grpc endpoint for.
	requests := []crawl.ObservedRequest{
		{
			Method:  "GET",
			URL:     srv.URL + "/v1/users/42",
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`{"id":"42"}`),
			},
		},
	}

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeGRPC,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, spec, "pure grpc-gateway REST capture with reflection off must still yield a non-empty .proto")

	// The swagger fixture tags every operation "UserService"; the generator
	// renders recovered services verbatim, so a genuine seed→probe→generate
	// assembly must surface it in the rendered .proto.
	assert.Contains(t, string(spec), "service UserService",
		"recovered grpc-gateway service name must be present in the generated .proto")

	// MUTATION-SENSITIVITY trace (why this test fails if any assembly step is
	// a no-op):
	//   - If seedGRPCHostEndpoints did not run (or returned classified
	//     unchanged): no endpoint carries APIType=="grpc", so
	//     probe.NewGRPCGatewayProbe.Probe's `if ep.APIType != "grpc"` guard
	//     skips every endpoint — servicesByHost stays empty, no HTTP request is
	//     ever made to srv, and no GRPCSchema is attached to anything.
	//   - With no GRPCSchema anywhere, generate/grpc.Generate's
	//     aggregateReflectionDescriptors and unionRecoveredServices both see
	//     zero contributions, `merged` stays empty, and Generate returns the
	//     explicit error "gRPC spec generation requires server reflection or
	//     recovered service names; none available" — this test's
	//     `require.NoError(t, err)` would fail immediately.
	//   - If seeding ran but the gateway probe never made a live fetch (e.g.
	//     probed a hand-built/stubbed schema instead of the network), the
	//     httptest.Server's /swagger.json handler is exactly what supplies
	//     "UserService" into GRPCSchema.Services; skipping that live fetch
	//     leaves GRPCSchema nil and produces the same "none available" error
	//     above.
	// Either failure mode is directly observable via this test's assertions,
	// so the assembly (not just its individual stages) is genuinely exercised.
}
