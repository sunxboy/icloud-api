package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"icloud-api/internal/domain"
)

// otpFormatHTMLPart is deliberately single-line so the archived HTML part can
// be compared byte for byte without depending on parser whitespace rules.
const otpFormatHTMLPart = `<html><body><a href="https://example.com/verify">Verify now</a><img src="https://cdn.example.com/logo.png"></body></html>`

func otpFormatRawMIME(otp string) []byte {
	return []byte("Subject: Your verification code\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"OTPBOUND\"\r\n" +
		"\r\n" +
		"--OTPBOUND\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Your code is " + otp + "\r\n" +
		"--OTPBOUND\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		otpFormatHTMLPart + "\r\n" +
		"--OTPBOUND--\r\n")
}

// otpFormatTextOnlyRawMIME deliberately puts markup-looking text in the body so
// the fallback path can prove it escapes rather than renders it.
func otpFormatTextOnlyRawMIME(otp string) []byte {
	return []byte("Subject: Your verification code\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Your code is " + otp + "\r\n" +
		"<b>not markup</b>\r\n")
}

type otpFormatEnv struct {
	env         *adminAPITestEnv
	router      http.Handler
	credentials domain.AliasCredentials
	derived     string
	emptyAPIKey string
}

// newOTPFormatEnv archives one HTML-bearing message for the primary alias and
// leaves a second alias on the same account with no records at all.
func newOTPFormatEnv(t *testing.T, otp string) otpFormatEnv {
	t.Helper()
	return newOTPFormatEnvWithMIME(t, otp, otpFormatRawMIME(otp))
}

func newOTPFormatEnvWithMIME(t *testing.T, otp string, rawMIME []byte) otpFormatEnv {
	t.Helper()
	env := newAdminAPITestEnv(t)
	env.server.sync = nil
	// The hand-built test config leaves this at zero; production always sets it
	// (ICLOUD_API_MAX_BODY_BYTES, validated to at least 1 KiB).
	env.server.cfg.MaxBodyBytes = 512 << 10
	if err := env.store.ConfigureMailArchive(t.TempDir(), 1<<20); err != nil {
		t.Fatalf("configure mail archive: %v", err)
	}
	account := adminAPITestCreateAccount(t, env, "otp-format@icloud.com")
	alias, credentials := createV2AliasFixture(t, env, account.ID, "otp-format-alias@icloud.com")

	received := time.Date(2026, 8, 11, 3, 0, 0, 0, time.UTC)
	loaded, err := env.store.GetAccount(context.Background(), account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.ApplyMailboxSync(
		context.Background(),
		account.ID,
		loaded.UpdatedAt,
		[]domain.Alias{alias},
		domain.MailboxSyncResult{
			ArchivedMessages: []domain.ArchivedMessage{{
				AccountID: account.ID, UIDValidity: 91, UID: 1,
				InternalDate: received, Subject: "Your verification code",
				RawMIME: rawMIME, OTP: otp, AliasIDs: []int64{alias.ID},
			}},
			State: domain.IMAPSyncState{
				AccountID: account.ID, UIDValidity: 91, LastUID: 1, UpdatedAt: received,
			},
			Reset: true,
		},
		received,
	); err != nil {
		t.Fatalf("archive HTML fixture: %v", err)
	}
	// Fail fast if the fixture failed to link the archived message to the
	// alias: otherwise every assertion below fails for the wrong reason.
	records, err := env.store.ListAliasOTPs(context.Background(), alias.ID, 10)
	if err != nil {
		t.Fatalf("verify fixture OTP archive: %v", err)
	}
	if len(records) != 1 || records[0].OTP != otp {
		var aliasRows, archivedRows int
		_ = env.store.DB().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM alias_messages WHERE alias_id = ?`, alias.ID).Scan(&aliasRows)
		_ = env.store.DB().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM archived_messages`).Scan(&archivedRows)
		t.Fatalf("fixture OTP archive = %#v; alias_messages=%d archived_messages=%d",
			records, aliasRows, archivedRows)
	}
	// The empty alias is created only after the sync: ApplyMailboxSync silently
	// discards a result whose enabled alias set no longer matches.
	_, emptyCredentials := createV2AliasFixture(t, env, account.ID, "otp-format-empty@icloud.com")

	router, err := env.server.Router()
	if err != nil {
		t.Fatalf("build public router: %v", err)
	}
	derived, err := env.cipher.OTPToken(alias.ID, alias.APIKeyHash)
	if err != nil {
		t.Fatal(err)
	}
	return otpFormatEnv{
		env:         env,
		router:      router,
		credentials: credentials,
		derived:     derived,
		emptyAPIKey: emptyCredentials.APIKey,
	}
}

func (fixture otpFormatEnv) get(t *testing.T, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	response := serveV2Request(fixture.router, http.MethodGet, path, "", headers)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q; want no-store", response.Header().Get("Cache-Control"))
	}
	return response
}

func TestOTPFormatPlainReturnsBareCode(t *testing.T) {
	for _, otp := range []string{"783448", "610-313"} {
		t.Run(otp, func(t *testing.T) {
			fixture := newOTPFormatEnv(t, otp)
			response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=plain", nil)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
			}
			if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/plain") {
				t.Fatalf("Content-Type = %q; want text/plain", mediaType)
			}
			if body := response.Body.String(); body != otp+"\n" {
				t.Fatalf("body = %q; want %q", body, otp+"\n")
			}
		})
	}
}

func TestOTPFormatPlainReturnsEmptyBodyWithoutRecords(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?format=plain", map[string]string{
		"Authorization": "Bearer " + fixture.emptyAPIKey,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/plain") {
		t.Fatalf("Content-Type = %q; want text/plain", mediaType)
	}
	if body := response.Body.String(); body != "" {
		t.Fatalf("body = %q; want zero bytes", body)
	}
}

func TestOTPFormatHTMLReturnsArchivedMarkupVerbatim(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html", mediaType)
	}
	if body := response.Body.String(); body != otpFormatHTMLPart {
		t.Fatalf("body = %q; want %q", body, otpFormatHTMLPart)
	}
}

// TestOTPFormatHTMLKeepsGlobalScriptProtections pins the security shape of the
// raw-HTML mode: only img-src and form-action may be relaxed. The directives
// that stop archived email HTML from executing or hijacking relative links must
// survive, because the OTP token in the URL is itself a credential.
func TestOTPFormatHTMLKeepsGlobalScriptProtections(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	policy := response.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"img-src https: data:",
		"form-action 'none'",
		"script-src 'self'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("Content-Security-Policy %q missing %q", policy, want)
		}
	}
}

// TestOTPFormatHTMLFallsBackToPlainText covers the message shape that must not
// look like an empty mailbox: a sender who wrote no HTML at all. The text is
// shown as text, so markup-looking content in it stays visible instead of
// becoming live markup.
func TestOTPFormatHTMLFallsBackToPlainText(t *testing.T) {
	fixture := newOTPFormatEnvWithMIME(t, "783448", otpFormatTextOnlyRawMIME("783448"))
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html", mediaType)
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "<pre>Your code is 783448") || !strings.HasSuffix(body, "</pre>") {
		t.Fatalf("body = %q; want the text body wrapped in <pre>", body)
	}
	if !strings.Contains(body, "&lt;b&gt;not markup&lt;/b&gt;") {
		t.Fatalf("body = %q; want the text escaped", body)
	}
	if strings.Contains(body, "<b>not markup") {
		t.Fatalf("body = %q; plain-text content leaked through as markup", body)
	}
}

// TestOTPHTMLContentSecurityPolicyDiffersInExactlyTwoDirectives stops the two
// literal policies from drifting apart as the global one evolves: the archived
// HTML view may relax image sources and form submissions, nothing else.
func TestOTPHTMLContentSecurityPolicyDiffersInExactlyTwoDirectives(t *testing.T) {
	global := strings.Split(contentSecurityPolicy, "; ")
	relaxed := strings.Split(otpHTMLContentSecurityPolicy, "; ")
	if len(global) != len(relaxed) {
		t.Fatalf("directive counts differ: global=%d otpHTML=%d", len(global), len(relaxed))
	}
	changed := make([]string, 0, len(global))
	for index, directive := range global {
		if directive == relaxed[index] {
			continue
		}
		name, _, _ := strings.Cut(directive, " ")
		if other, _, _ := strings.Cut(relaxed[index], " "); other != name {
			t.Fatalf("directive %d changed from %q to %q", index, directive, relaxed[index])
		}
		changed = append(changed, name)
	}
	if strings.Join(changed, " ") != "img-src form-action" {
		t.Fatalf("changed directives = %v; want exactly [img-src form-action]", changed)
	}
}

func TestOTPFormatNonHTMLKeepsStrictContentSecurityPolicy(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	for _, path := range []string{
		"/api/v1/otp?token=" + url.QueryEscape(fixture.derived),
		"/api/v1/otp?token=" + url.QueryEscape(fixture.derived) + "&format=plain",
	} {
		response := fixture.get(t, path, nil)
		policy := response.Header().Get("Content-Security-Policy")
		if !strings.Contains(policy, "img-src 'self' data:") {
			t.Fatalf("Content-Security-Policy %q for %s lost the strict img-src", policy, path)
		}
	}
}

func TestOTPFormatHTMLReturnsEmptyBodyWithoutRecords(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?format=html", map[string]string{
		"Authorization": "Bearer " + fixture.emptyAPIKey,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html", mediaType)
	}
	if body := response.Body.String(); body != "" {
		t.Fatalf("body = %q; want zero bytes", body)
	}
}

// TestOTPFormatHTMLReportsUnavailableArchivedContent covers the case the empty
// state must NOT hide: an OTP row proves the message arrived, so a missing
// archive body is an error worth surfacing rather than a blank page.
func TestOTPFormatHTMLReportsUnavailableArchivedContent(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	if _, err := fixture.env.store.DB().ExecContext(
		context.Background(),
		`UPDATE archived_messages SET content_path = '', content_state = 'evicted'
		 WHERE uid_validity = 91 AND upstream_uid = 1`,
	); err != nil {
		t.Fatalf("evict archived content: %v", err)
	}
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "MAIL_CONTENT_UNAVAILABLE") {
		t.Fatalf("body = %q; want MAIL_CONTENT_UNAVAILABLE", body)
	}
}

// TestOTPFormatHTMLReportsCorruptedArchivedContentAsUnavailable covers the
// branch that reports a bare error instead of store.ErrNotFound. The caller
// must still see "content unavailable": reporting a database failure there
// would contradict the documented contract and the IMAPS placeholder path.
func TestOTPFormatHTMLReportsCorruptedArchivedContentAsUnavailable(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	if _, err := fixture.env.store.DB().ExecContext(
		context.Background(),
		`UPDATE archived_messages SET content_bytes = content_bytes + 1
		 WHERE uid_validity = 91 AND upstream_uid = 1`,
	); err != nil {
		t.Fatalf("corrupt archived content size: %v", err)
	}
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "MAIL_CONTENT_UNAVAILABLE") {
		t.Fatalf("body = %q; want MAIL_CONTENT_UNAVAILABLE", body)
	}
}

// TestOTPFormatPlainStillWorksWhenArchivedContentIsEvicted pins that the bare
// code path never depends on the on-disk archive, which may be evicted.
func TestOTPFormatPlainStillWorksWhenArchivedContentIsEvicted(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	if _, err := fixture.env.store.DB().ExecContext(
		context.Background(),
		`UPDATE archived_messages SET content_path = '', content_state = 'evicted'
		 WHERE uid_validity = 91 AND upstream_uid = 1`,
	); err != nil {
		t.Fatalf("evict archived content: %v", err)
	}
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=plain", nil)
	if response.Code != http.StatusOK || response.Body.String() != "783448\n" {
		t.Fatalf("status = %d body = %q; want 200 %q", response.Code, response.Body.String(), "783448\n")
	}
}

// TestOTPFormatQueryWhitelistRejectsEverythingElse keeps the original 401
// sources intact while allowing exactly one optional format parameter.
func TestOTPFormatQueryWhitelistRejectsEverythingElse(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	token := url.QueryEscape(fixture.derived)
	for name, tc := range map[string]struct {
		path    string
		headers map[string]string
	}{
		"unknown parameter":    {path: "/api/v1/otp?token=" + token + "&next=elsewhere"},
		"invalid format":       {path: "/api/v1/otp?token=" + token + "&format=bogus"},
		"empty format":         {path: "/api/v1/otp?token=" + token + "&format="},
		"duplicate format":     {path: "/api/v1/otp?token=" + token + "&format=plain&format=html"},
		"format without token": {path: "/api/v1/otp?format=plain"},
		"duplicate token":      {path: "/api/v1/otp?token=" + token + "&token=" + token},
		"format plus bearer": {
			path:    "/api/v1/otp?token=" + token + "&format=plain",
			headers: map[string]string{"Authorization": "Bearer " + fixture.credentials.APIKey},
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := serveV2Request(fixture.router, http.MethodGet, tc.path, "", tc.headers)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
			}
			if body := response.Body.String(); !strings.Contains(body, "INVALID_API_KEY") {
				t.Fatalf("body = %q; want INVALID_API_KEY", body)
			}
		})
	}
}

// TestOTPWithoutFormatIsUnchanged guards the compatibility promise: every
// request that does not opt into a format keeps the original JSON contract.
func TestOTPWithoutFormatIsUnchanged(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "application/json") {
		t.Fatalf("Content-Type = %q; want application/json", mediaType)
	}
	if body := response.Body.String(); !strings.Contains(body, `"otp":"783448"`) {
		t.Fatalf("body = %q; want the original JSON record shape", body)
	}
}
