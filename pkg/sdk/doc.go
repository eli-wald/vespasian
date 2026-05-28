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

// Package sdk exposes vespasian as a capability-sdk Capability so the
// chariot platform (and other capability-sdk consumers) can run the
// crawl → classify → probe → generate pipeline through the standard
// capability.Capability[capmodel.WebApplication] interface.
//
// Consumers register this capability via their host's SDK registration
// hook (e.g. chariot's registries.RegisterSDKCapability). The standalone
// vespasian CLI does not import this package; it remains the
// authoritative end-user surface and is unaffected by changes here.
package sdk
