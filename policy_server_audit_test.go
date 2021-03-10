package sshaudit

import (
	"testing"
)

func TestPolicyServerAudit(t *testing.T) {
	c := testClient(t)
	c.BaseURL = mockResponse("policy_server_audit.json").URL
	_, err := c.PolicyServerAudit(
		"example.com",
		22,
		"Hardened Ubuntu Server 18.04 LTS (version 1)",
	)
	if err != nil {
		t.Errorf("must be no error. got %v", err)
	}
}
