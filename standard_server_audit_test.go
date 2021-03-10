package sshaudit

import (
	"testing"
)

func TestStandardServerAudit(t *testing.T) {
	c := testClient(t)
	c.BaseURL = mockResponse("standard_server_audit.json").URL
	_, err := c.StandardServerAudit("example.com", 22)
	if err != nil {
		t.Errorf("must be no error. got %v", err)
	}
}
