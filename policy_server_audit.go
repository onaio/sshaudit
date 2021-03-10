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

	payload := &url.Values{}
	payload.Add("s", server)
	payload.Add("p", strconv.Itoa(port))
	payload.Add("audit_type", "policy")
	payload.Add("policy_name", policyName)
	payload.Add("csrf_token", pingInfo.CSRFToken)

	url := fmt.Sprintf("%s/server_audit", c.BaseURL)
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
