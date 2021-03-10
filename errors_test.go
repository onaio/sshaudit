package sshaudit

import (
	"errors"
	"testing"
)

func TestHTTPClientError_Error(t *testing.T) {
	e := &HTTPClientError{
		StatusCode: 469,
		Err:        errors.New("error message"),
	}
	expected := "status 469, err: error message"
	if got := e.Error(); got != expected {
		t.Errorf("HTTPClientError.Error() = %v, want %v", got, expected)
	}
}
