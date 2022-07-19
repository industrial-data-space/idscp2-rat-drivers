package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"
)

type PolicyFactory func(params json.RawMessage) (Policy, error)

var registeredPolicies = map[string]PolicyFactory{
	// Register all default policies
	"equals":          EqualsFactory,
	"greaterEqual":    GreaterEqualFactory,
	"tcbGreaterEqual": TcbGreaterEqualFactory,
}

func RegisterPolicy(name string, factory PolicyFactory) {
	registeredPolicies[name] = factory
}

// The json representation of a policy
type policyJson struct {
	PolicyType string          `json:"type"`
	Id         string          `json:"id,omitempty"`
	Params     json.RawMessage `json:"params"`
}

type PolicyWrapper struct {
	Id      string
	Wrapped Policy
}

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
