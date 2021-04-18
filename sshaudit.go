package sshaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"time"
)

// VERSION is current package version.
const VERSION = "0.1.0"

const baseURL = "https://www.sshaudit.com"

// PingInfo holds information from a sshaudit.com/ping response.
type PingInfo struct {
	CSRFToken         string   `json:"csrf_token"`
	ServerPolicyNames []string `json:"server_policy_names"`
	ClientPolicyNames []string `json:"client_policy_names"`
}

// Client represents an SSH Audit client.
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	UserAgent  string
}

// NewClient constructs a client using http.DefaultClient and the default
// base URL.
func NewClient(app, version string) (*Client, error) {
	if app == "" {
		return nil, errors.New("App name must not be empty")
	}

	if version == "" {
		return nil, errors.New("Version must not be empty")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Client{
		HTTPClient: &http.Client{
			Jar:     jar,
			Timeout: time.Second * 10,
		},
		BaseURL:   baseURL,
		UserAgent: getUserAgent(app, version),
	}, nil
}

func (c *Client) ping() (*PingInfo, error) {
	var pingInfo PingInfo

	url := fmt.Sprintf("%s/ping", c.BaseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	err = c.do(req, &pingInfo)
	if err != nil {
		return nil, err
	}

	return &pingInfo, nil
}

func (c *Client) do(req *http.Request, result interface{}) error {
	if req == nil {
		return errors.New("nil request")
	}

	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", c.UserAgent)
	url := req.URL.RequestURI()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failure on %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return makeHTTPClientError(url, resp)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("HTTP Read error on response for %s: %w", url, err)
	}

	err = json.Unmarshal(b, result)
	if err != nil {
		return fmt.Errorf("JSON decode failed on %s:\n%s\nerror: %w",
			url, string(b), err,
		)
	}

	return nil
}

// getUserAgent generates User-Agent string for client.
func getUserAgent(app, version string) string {
	if app != "" && version != "" {
		return fmt.Sprintf(
			"%s/%s SSHAudit/%s (go; %s; %s-%s)",
			app, version, VERSION, runtime.Version(),
			runtime.GOARCH, runtime.GOOS,
		)
	}

	return fmt.Sprintf(
		"SSHAudit/%s (go; %s; %s-%s)",
		VERSION, runtime.Version(),
		runtime.GOARCH, runtime.GOOS,
	)
}
