/*-
 * ========================LICENSE_START=================================
 * snp-attestd
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

// A function that can construct a policy instance from its parameters encoded as json.
type PolicyFactory func(params json.RawMessage) (Policy, error)

var registeredPolicies = map[string]PolicyFactory{
	// Register all default policies
	"equals":          EqualsFactory,
	"greaterEqual":    GreaterEqualFactory,
	"tcbGreaterEqual": TcbGreaterEqualFactory,
}

// Register a new policy to be recognized by the policy runner.
// A policy is identified by a name and then constructed from its parameters using a policy
// factory.
func RegisterPolicy(name string, factory PolicyFactory) {
	registeredPolicies[name] = factory
}

// The json representation of a policy
type policyJson struct {
	PolicyType string          `json:"type"`
	Id         string          `json:"id,omitempty"`
	Params     json.RawMessage `json:"params"`
}

// The PolicyWrapper struct is used to associate a policy with its Id.
// If the policy has no Id, it is omitted.
type PolicyWrapper struct {
	Id      string
	Wrapped Policy
}

// Parse an array of policies encoded as json.
func ParsePolicies(encoded []byte) ([]PolicyWrapper, error) {
	var rawPolicies []policyJson
	err := json.Unmarshal(encoded, &rawPolicies)
	if err != nil {
		return []PolicyWrapper{}, fmt.Errorf("error parsing policies from json: %w", err)
	}

	wrappers := make([]PolicyWrapper, len(rawPolicies))
	for i, rawPolicy := range rawPolicies {
		policyFactory, ok := registeredPolicies[rawPolicy.PolicyType]
		if !ok {
			return []PolicyWrapper{}, fmt.Errorf("unknown policy type: %s", rawPolicy.PolicyType)
		}

		policy, err := policyFactory(rawPolicy.Params)
		if err != nil {
			return []PolicyWrapper{}, fmt.Errorf(
				"could not instantiate policy %s with given parameters: %w",
				rawPolicy.PolicyType,
				err,
			)
		}

		wrappers[i] = PolicyWrapper{
			Id:      rawPolicy.Id,
			Wrapped: policy,
		}
	}

	return wrappers, nil
}

// Check if an attestation report conforms to a set of policies.
// The report is rejected, if a single policy is not satisfied by the attestation report.
// For each failed policy, a string giving the reason for failure is returned.
// If an error is encountered, policy checking is halted and the error returned.
func CheckPolicies(
	policies []PolicyWrapper,
	ar *ar.AttestationReport,
) (allOk bool, reasons string, err error) {
	var reasonsBuilder strings.Builder

	// Since we have done nothing yet, all previous policies checked out OK :)
	allOk = true
	for _, policy := range policies {
		ok, reason, err2 := policy.Wrapped.CheckReport(ar)

		// Internal error: abort
		if err2 != nil {
			var policyName string
			// Only include the policy Id if not null
			if policy.Id != "" {
				policyName = " " + policy.Id
			}
			err = fmt.Errorf("error validating policy%s: %w", policyName, err2)
			return
		}

		// Policy failed
		if !ok {
			allOk = false
			reasonsBuilder.WriteString("Policy ")
			if policy.Id != "" {
				reasonsBuilder.WriteString(policy.Id)
				reasonsBuilder.WriteRune(' ')
			}
			reasonsBuilder.WriteString("failed: ")
			reasonsBuilder.WriteString(reason)
			reasonsBuilder.WriteRune('\n')
		}
	}

	if !allOk {
		reasons = reasonsBuilder.String()
	}
	return
}
