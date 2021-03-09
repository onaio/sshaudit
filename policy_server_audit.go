package sshaudit

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PolicyServerAuditInfo holds response from a policy server audit.
type PolicyServerAuditInfo struct {
	AuditType      string         `json:"audit_type"`
	TargetServer   string         `json:"target_server"`
	TargetServerIP string         `json:"target_server_ip"`
	PolicyName     string         `json:"policy_name"`
	Passed         bool           `json:"passed"`
	PolicyErrors   []*PolicyError `json:"policy_errors"`
}

// PolicyError holds information on policy errors from an audit.
type PolicyError struct {
	Actual           []string `json:"actual"`
	ExpectedOptional []string `json:"expected_optional"`
	ExpectedRequired []string `json:"expected_required"`
	MismatchedField  string   `json:"mismatched_field"`
}

// PolicyServerAudit runs a policy server audit on a given server.
//
// A policy audit determines if the target adheres to a specific set of
// expected options. The resulting score is either pass or fail.
// Policy audits are useful for ensuring a server has been successfully
// (and remains) hardened.
func (c *Client) PolicyServerAudit(server string, port int, policyName string) (*PolicyServerAuditInfo, error) {
	var policyServerAuditInfo PolicyServerAuditInfo

	pingInfo, err := c.ping()
	if err != nil {
		return nil, err
	}

	// validate policyName is in server_policy_names from ping response
	if !contains(pingInfo.ServerPolicyNames, policyName) {
		return nil, fmt.Errorf(
			"Invalid policy name '%s' provided.\nValid policy names are: %v",
			policyName, pingInfo.ServerPolicyNames,
		)
	}

	payload := &url.Values{}
	payload.Add("s", server)
	payload.Add("p", strconv.Itoa(port))
	payload.Add("audit_type", "policy")
	payload.Add("policy_name", policyName)
	payload.Add("csrf_token", pingInfo.CSRFToken)

	url := fmt.Sprintf("%s/server_audit", baseURL)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}

	err = c.do(req, &policyServerAuditInfo)
	if err != nil {
		return nil, err
	}

	return &policyServerAuditInfo, nil
}

// contains checks if val is present in a slice.
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}

	return false
}
