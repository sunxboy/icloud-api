package httpserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"icloud-api/internal/secure"
)

// otpUnknownToken returns a syntactically valid API key that cannot resolve to
// an alias, which is what a scanner guessing tokens sends.
func otpUnknownToken(t *testing.T) string {
	t.Helper()
	secret, err := secure.RandomToken(32)
	if err != nil {
		t.Fatalf("generate unknown token: %v", err)
	}
	return "icm_" + secret
}

func TestOTPInvalidTokenThrottledPerIP(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	path := "/api/v1/otp?token=" + url.QueryEscape(otpUnknownToken(t))
	for attempt := 1; attempt <= 30; attempt++ {
		response := serveV2Request(fixture.router, http.MethodGet, path, "", nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d; body=%q", attempt, response.Code, response.Body.String())
		}
	}
	response := serveV2Request(fixture.router, http.MethodGet, path, "", nil)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled status = %d; body=%q", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "RATE_LIMITED") {
		t.Fatalf("throttled body = %q; want RATE_LIMITED", body)
	}
}

func TestOTPValidTokenNeverThrottled(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	path := "/api/v1/otp?token=" + url.QueryEscape(fixture.derived)
	for attempt := 1; attempt <= 60; attempt++ {
		response := serveV2Request(fixture.router, http.MethodGet, path, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d; body=%q", attempt, response.Code, response.Body.String())
		}
	}
}

func TestOTPValidRequestsDoNotConsumeInvalidBudget(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	invalidPath := "/api/v1/otp?token=" + url.QueryEscape(otpUnknownToken(t))
	validPath := "/api/v1/otp?token=" + url.QueryEscape(fixture.derived)

	for attempt := 1; attempt <= 25; attempt++ {
		if response := serveV2Request(fixture.router, http.MethodGet, invalidPath, "", nil); response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid attempt %d status = %d", attempt, response.Code)
		}
	}
	for attempt := 1; attempt <= 20; attempt++ {
		if response := serveV2Request(fixture.router, http.MethodGet, validPath, "", nil); response.Code != http.StatusOK {
			t.Fatalf("valid attempt %d status = %d", attempt, response.Code)
		}
	}
	for attempt := 26; attempt <= 30; attempt++ {
		if response := serveV2Request(fixture.router, http.MethodGet, invalidPath, "", nil); response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid attempt %d status = %d", attempt, response.Code)
		}
	}
	if response := serveV2Request(fixture.router, http.MethodGet, invalidPath, "", nil); response.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled status = %d; want 429", response.Code)
	}
}

func TestOTPHTMLInvalidTokenAlwaysReturnsBlankPage(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	path := "/api/v1/otp?token=" + url.QueryEscape(otpUnknownToken(t)) + "&format=html"
	// The 31st request exceeds the invalid-token budget but must stay blank.
	for attempt := 1; attempt <= 31; attempt++ {
		response := serveV2Request(fixture.router, http.MethodGet, path, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d; body=%q", attempt, response.Code, response.Body.String())
		}
		if response.Body.Len() != 0 {
			t.Fatalf("attempt %d body = %q; want blank", attempt, response.Body.String())
		}
		if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
			t.Fatalf("attempt %d Content-Type = %q; want text/html", attempt, mediaType)
		}
	}
}

func TestOTPHTMLMalformedQueryReturnsBlankPage(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	token := url.QueryEscape(fixture.derived)
	for name, path := range map[string]string{
		"invalid message": "/api/v1/otp?token=" + token + "&format=html&message=abc",
		"missing token":   "/api/v1/otp?format=html&message=1",
		"unknown param":   "/api/v1/otp?token=" + token + "&format=html&next=elsewhere",
	} {
		t.Run(name, func(t *testing.T) {
			response := serveV2Request(fixture.router, http.MethodGet, path, "", nil)
			if response.Code != http.StatusOK || response.Body.Len() != 0 {
				t.Fatalf("status = %d body = %q; want blank 200", response.Code, response.Body.String())
			}
		})
	}
}

func TestOTPPlainInvalidTokenKeepsJSONError(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	path := "/api/v1/otp?token=" + url.QueryEscape(otpUnknownToken(t)) + "&format=plain"
	response := serveV2Request(fixture.router, http.MethodGet, path, "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "INVALID_API_KEY") {
		t.Fatalf("body = %q; want INVALID_API_KEY", body)
	}
}
