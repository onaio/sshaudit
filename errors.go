package sshaudit

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

// HTTPClientError custom error to handle with response status.
type HTTPClientError struct {
	StatusCode int
	Err        error
}

func (e *HTTPClientError) Error() string {
	return fmt.Sprintf("status %d, err: %v", e.StatusCode, e.Err)
}

func makeHTTPClientError(url string, resp *http.Response) error {
	var respErr error

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		respErr = fmt.Errorf(
			"HTTP request failure on %s with status %d\nCannot parse body with: %w",
			url, resp.StatusCode, err,
		)
	} else {
		respErr = fmt.Errorf(
			"HTTP request failure on %s with status %d\nBody: %v",
			url, resp.StatusCode, string(body),
		)
	}

	return &HTTPClientError{
		StatusCode: resp.StatusCode,
		Err:        respErr,
	}
}
