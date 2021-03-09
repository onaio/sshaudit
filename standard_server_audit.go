package sshaudit

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// StandardServerAuditInfo holds results from a standard server audit.
type StandardServerAuditInfo struct {
	AuditType         string                      `json:"audit_type"`
	Banner            string                      `json:"banner"`
	Kex               []*AuditNote                `json:"kex"`
	Key               []*AuditNote                `json:"key"`
	Enc               []*AuditNote                `json:"enc"`
	Mac               []*AuditNote                `json:"mac"`
	Fin               []string                    `json:"fin"`
	Score             int                         `json:"score"`
	Grade             string                      `json:"grade"`
	Version           string                      `json:"version"`
	TargetServer      string                      `json:"target_server"`
	TargetServerPort  int                         `json:"target_server_port"`
	TargetServerIP    string                      `json:"target_server_ip"`
	Findings          []*Finding                  `json:"findings"`
	CategorySummaries map[string]*CategorySummary `json:"category_summaries"`
}

// AuditNote holds information on a given algorithm identified in a scan.
type AuditNote struct {
	Name        string `json:"name"`
	Class       int    `json:"class"`
	ScoreCap    int    `json:"score_cap"`
	ScoreAdjust int    `json:"score_adjust"`
	Notes       string `json:"notes"`
}

// Finding holds details of issues identified during scan.
type Finding struct {
	FindingSummaryTitle string   `json:"finding_summary_title"`
	FindingSummaryBody  string   `json:"finding_summary_body"`
	FindingSolution     string   `json:"finding_solution"`
	FindingReferences   []string `json:"finding_references"`
	FindingAffected     []string `json:"finding_affected"`
}

// CategorySummary holds a summary of good algorithms and total algorithms.
type CategorySummary struct {
	GoodAlgs  int `json:"good_algs"`
	TotalAlgs int `json:"total_algs"`
}

// StandardServerAudit runs a standard server audit on a given server.
//
// A standard audit evaluates each of the individual cryptographic algorithms
// supported by the target. An overall score is given based on how many strong,
// acceptable, and weak options are available.
func (c *Client) StandardServerAudit(server string, port int) (*StandardServerAuditInfo, error) {
	var standardServerAuditInfo StandardServerAuditInfo

	pingInfo, err := c.ping()
	if err != nil {
		return nil, err
	}

	payload := &url.Values{}
	payload.Add("s", server)
	payload.Add("p", strconv.Itoa(port))
	payload.Add("audit_type", "standard")
	payload.Add("csrf_token", pingInfo.CSRFToken)

	url := fmt.Sprintf("%s/server_audit", baseURL)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}

	err = c.do(req, &standardServerAuditInfo)
	if err != nil {
		return nil, err
	}

	return &standardServerAuditInfo, nil
}
