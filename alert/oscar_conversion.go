// Copyright 2018 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ConversionResolutionReceipt identifies the exact current entry, not source authority.
// It is projected only by native GET and checked under the provider mutation mutex.
func ConversionResolutionReceipt(a *Alert) string {
	value, _ := json.Marshal(struct {
		Labels, Annotations         any
		StartsAt, EndsAt, UpdatedAt any
		GeneratorURL                string
		Timeout                     bool
	}{a.Labels, a.Annotations, a.StartsAt, a.EndsAt, a.UpdatedAt, a.GeneratorURL, a.Timeout})
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
