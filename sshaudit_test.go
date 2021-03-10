package sshaudit

import (
	"errors"
	"log"
	"net/http"
	"testing"
)

func testClient(t *testing.T) *Client {
	client, err := NewClient("testApp", "0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	return client
}

func TestClient_do(t *testing.T) {
	c := testClient(t)
	url := mockErrorResponse(400).URL

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = c.do(req, nil)
	var e *HTTPClientError
	if errors.Is(err, e) {
		t.Errorf("should be an http error, but was not: %v", err)
	}

	err = c.do(nil, nil)
	if err == nil {
		t.Error("there should be an error, but was nil")
	}
}
