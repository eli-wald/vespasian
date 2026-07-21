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

// Package httpx builds proxy-aware HTTP clients and dialers shared by the probe,
// WSDL-discovery, JS-replay, and sourcemap stages. It is a stdlib-only leaf
// (plus golang.org/x/net/proxy for SOCKS5) and imports nothing from crawl,
// probe, pipeline, or ssrf, so every consumer can depend on it without a cycle.
//
// The proxy-aware transport mirrors pkg/crawl/http_crawler.go's proxy branch:
// with a proxy configured the client dials the proxy (commonly loopback), not
// the target, so the dial-time SSRF guard is deliberately NOT installed. Target
// scope stays enforced at the URL level by each consumer's own validators.
package httpx
