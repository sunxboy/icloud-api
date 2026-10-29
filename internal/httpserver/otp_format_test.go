package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	xhtml "golang.org/x/net/html"

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
	env          *adminAPITestEnv
	router       http.Handler
	credentials  domain.AliasCredentials
	derived      string
	emptyAPIKey  string
	accountID    int64
	aliasID      int64
	emptyAliasID int64
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
	// The hand-built test config leaves these at zero; production always sets
	// them (ICLOUD_API_MAX_BODY_BYTES is validated to at least 1 KiB).
	env.server.cfg.MaxBodyBytes = 512 << 10
	env.server.cfg.Timezone = time.UTC
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
	emptyAlias, emptyCredentials := createV2AliasFixture(t, env, account.ID, "otp-format-empty@icloud.com")

	router, err := env.server.Router()
	if err != nil {
		t.Fatalf("build public router: %v", err)
	}
	derived, err := env.cipher.OTPToken(alias.ID, alias.APIKeyHash)
	if err != nil {
		t.Fatal(err)
	}
	return otpFormatEnv{
		env:          env,
		router:       router,
		credentials:  credentials,
		derived:      derived,
		emptyAPIKey:  emptyCredentials.APIKey,
		accountID:    account.ID,
		aliasID:      alias.ID,
		emptyAliasID: emptyAlias.ID,
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

func (fixture otpFormatEnv) messageID(t *testing.T) int64 {
	t.Helper()
	records, err := fixture.env.store.ListAliasOTPs(context.Background(), fixture.aliasID, 10)
	if err != nil {
		t.Fatalf("list OTP records: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("fixture has no archived OTP message")
	}
	return records[0].MessageID
}

// otpFormatIframeSrcDoc returns the reader's srcdoc after the HTML parser has
// undone attribute escaping, which is the same byte sequence the browser feeds
// into the sandboxed frame.
func otpFormatIframeSrcDoc(t *testing.T, body string) string {
	t.Helper()
	document, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse reader HTML: %v", err)
	}
	var srcdoc string
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode && node.Data == "iframe" {
			for _, attribute := range node.Attr {
				if attribute.Key == "srcdoc" {
					srcdoc = attribute.Val
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	if srcdoc == "" {
		t.Fatalf("reader HTML has no srcdoc body: %q", body)
	}
	return srcdoc
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

func TestOTPFormatHTMLListsArchivedMessages(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html", mediaType)
	}
	body := response.Body.String()
	for _, want := range []string{
		"邮件 (1)",
		"otp-format-alias@icloud.com",
		"发件人",
		"主题",
		"时间",
		"操作",
		"Your verification code",
		"2026-08-11 03:00",
		`aria-label="阅读"`,
		"收取邮件",
		"fetch=1&amp;format=html&amp;token=",
		"format=html&amp;message=" + strconv.FormatInt(fixture.messageID(t), 10) + "&amp;token=",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("list body missing %q; body=%q", want, body)
		}
	}
	if strings.Contains(body, otpFormatHTMLPart) {
		t.Fatalf("list body leaked the archived markup verbatim: %q", body)
	}
	if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "img-src 'self' data:") {
		t.Fatalf("list CSP %q is not the strict policy", policy)
	}
}

// TestOTPFormatHTMLListsMessagesWithoutOTP pins the scope of the inbox view:
// it is the alias's mailbox, not just the rows an OTP was extracted from.
func TestOTPFormatHTMLListsMessagesWithoutOTP(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	ctx := context.Background()
	aliases, err := fixture.env.store.ListAliases(ctx, fixture.accountID)
	if err != nil {
		t.Fatalf("list aliases: %v", err)
	}
	received := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	rawMIME := []byte("Subject: Tracking Issue Alert\r\n" +
		"From: SHEIN <noreply@sheinnotice.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Your parcel is delayed.\r\n")
	account, err := fixture.env.store.GetAccount(ctx, fixture.accountID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if err := fixture.env.store.ApplyMailboxSync(
		ctx,
		fixture.accountID,
		account.UpdatedAt,
		aliases,
		domain.MailboxSyncResult{
			ArchivedMessages: []domain.ArchivedMessage{{
				AccountID: fixture.accountID, UIDValidity: 91, UID: 2,
				InternalDate: received, Subject: "Tracking Issue Alert",
				From:    []domain.MailAddress{{Name: "SHEIN", Email: "noreply@sheinnotice.com"}},
				RawMIME: rawMIME, AliasIDs: []int64{fixture.aliasID},
			}},
			State: domain.IMAPSyncState{
				AccountID: fixture.accountID, UIDValidity: 91, LastUID: 2, UpdatedAt: received,
			},
			// Creating the empty alias invalidated the first fixture sync's
			// cursor, so this second publish has to establish a baseline.
			Reset: true,
		},
		received,
	); err != nil {
		t.Fatalf("archive second message: %v", err)
	}

	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		"邮件 (2)",
		"Tracking Issue Alert",
		"SHEIN &lt;noreply@sheinnotice.com&gt;",
		"Your verification code",
		"2026-08-12 03:00",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("list body missing %q; body=%q", want, body)
		}
	}
	if strings.Index(body, "Tracking Issue Alert") > strings.Index(body, "Your verification code") {
		t.Fatalf("list is not newest first: %q", body)
	}
}

// TestOTPFormatHTMLReadsArchivedMarkupVerbatim pins that the reader still
// hands the sender's HTML to the browser byte for byte; the sandboxed iframe is
// the boundary that keeps it from restyling or scripting the page shell.
func TestOTPFormatHTMLReadsArchivedMarkupVerbatim(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	messageID := fixture.messageID(t)
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+
		"&format=html&message="+strconv.FormatInt(messageID, 10), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html", mediaType)
	}
	body := response.Body.String()
	if srcdoc := otpFormatIframeSrcDoc(t, body); srcdoc != otpFormatHTMLPart {
		t.Fatalf("srcdoc = %q; want %q", srcdoc, otpFormatHTMLPart)
	}
	for _, want := range []string{
		"← 返回列表",
		"Your verification code",
		"未知发件人",
		"2026-08-11 03:00",
		"format=html&amp;token=",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("reader body missing %q; body=%q", want, body)
		}
	}
	if strings.Contains(body, "message=") {
		t.Fatalf("reader back link still carries the message selector: %q", body)
	}
}

// TestOTPFormatHTMLKeepsGlobalScriptProtections pins the security shape of the
// reader: only img-src and form-action may be relaxed. The directives that stop
// archived email HTML from executing or hijacking relative links must survive,
// because the OTP token in the URL is itself a credential.
func TestOTPFormatHTMLKeepsGlobalScriptProtections(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+
		"&format=html&message="+strconv.FormatInt(fixture.messageID(t), 10), nil)
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
	if body := response.Body.String(); !strings.Contains(body, `sandbox="allow-same-origin`) ||
		strings.Contains(body, "allow-scripts") {
		t.Fatalf("reader iframe sandbox is wrong: %q", body)
	}
}

// TestOTPFormatHTMLFallsBackToPlainText covers the message shape that must not
// look like an empty mailbox: a sender who wrote no HTML at all. The text is
// shown as text, so markup-looking content in it stays visible instead of
// becoming live markup.
func TestOTPFormatHTMLFallsBackToPlainText(t *testing.T) {
	fixture := newOTPFormatEnvWithMIME(t, "783448", otpFormatTextOnlyRawMIME("783448"))
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+
		"&format=html&message="+strconv.FormatInt(fixture.messageID(t), 10), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if mediaType := response.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html", mediaType)
	}
	srcdoc := otpFormatIframeSrcDoc(t, response.Body.String())
	if !strings.HasPrefix(srcdoc, "<pre>Your code is 783448") || !strings.HasSuffix(srcdoc, "</pre>") {
		t.Fatalf("srcdoc = %q; want the text body wrapped in <pre>", srcdoc)
	}
	if !strings.Contains(srcdoc, "&lt;b&gt;not markup&lt;/b&gt;") {
		t.Fatalf("srcdoc = %q; want the text escaped", srcdoc)
	}
	if strings.Contains(srcdoc, "<b>not markup") {
		t.Fatalf("srcdoc = %q; plain-text content leaked through as markup", srcdoc)
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

const otpFetchNotice = "已请求收取，请稍后再次点击查看"

// TestOTPFormatHTMLRendersInboxShellWithoutRecords pins ADR 0003: an alias with
// no archived mail still gets the inbox page, with the address slot masked.
func TestOTPFormatHTMLRendersInboxShellWithoutRecords(t *testing.T) {
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
	body := response.Body.String()
	for _, want := range []string{
		"邮件 (0)",
		`<p class="alias">—</p>`,
		`href="/api/v1/otp?fetch=1&amp;format=html"`,
		"收取邮件",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("shell body missing %q; body=%q", want, body)
		}
	}
	if strings.Contains(body, "<td") {
		t.Fatalf("shell body lists rows for an empty mailbox: %q", body)
	}
	if strings.Contains(body, otpFetchNotice) {
		t.Fatalf("shell body shows the fetch notice without fetch=1: %q", body)
	}
}

// TestOTPFormatHTMLInvalidCredentialsLookLikeEmptyMailbox pins the anti-probing
// rule of ADR 0003: status, headers and page body must not reveal whether the
// credential was accepted.
func TestOTPFormatHTMLInvalidCredentialsLookLikeEmptyMailbox(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	valid := fixture.get(t, "/api/v1/otp?format=html", map[string]string{
		"Authorization": "Bearer " + fixture.emptyAPIKey,
	})
	if !strings.Contains(valid.Body.String(), "收取邮件") {
		t.Fatalf("empty mailbox did not render the shell: %q", valid.Body.String())
	}
	for name, headers := range map[string]map[string]string{
		"unknown bearer":   {"Authorization": "Bearer " + strings.Repeat("a", len(fixture.emptyAPIKey))},
		"malformed bearer": {"Authorization": "Bearer nope"},
		"no credential":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			response := fixture.get(t, "/api/v1/otp?format=html", headers)
			if response.Code != valid.Code {
				t.Fatalf("status = %d; want %d", response.Code, valid.Code)
			}
			if got, want := response.Header().Get("Content-Type"), valid.Header().Get("Content-Type"); got != want {
				t.Fatalf("Content-Type = %q; want %q", got, want)
			}
			if got, want := response.Body.String(), valid.Body.String(); got != want {
				t.Fatalf("invalid credential body differs from empty mailbox\ngot:  %q\nwant: %q", got, want)
			}
		})
	}
	bogus := fixture.get(t, "/api/v1/otp?format=html&token=bogus", nil)
	for _, want := range []string{"邮件 (0)", `<p class="alias">—</p>`, "收取邮件"} {
		if !strings.Contains(bogus.Body.String(), want) {
			t.Fatalf("bogus token body missing %q; body=%q", want, bogus.Body.String())
		}
	}
	if strings.Contains(bogus.Body.String(), "<td") {
		t.Fatalf("bogus token page lists rows: %q", bogus.Body.String())
	}
}

// TestOTPFormatHTMLFetchNoticeDependsOnlyOnFetchParameter pins that the notice
// row cannot be used to tell valid credentials from invalid ones.
func TestOTPFormatHTMLFetchNoticeDependsOnlyOnFetchParameter(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	token := url.QueryEscape(fixture.derived)
	for name, tc := range map[string]struct {
		path    string
		headers map[string]string
	}{
		"valid with mail":    {path: "/api/v1/otp?format=html&fetch=1&token=" + token},
		"valid without mail": {path: "/api/v1/otp?format=html&fetch=1", headers: map[string]string{"Authorization": "Bearer " + fixture.emptyAPIKey}},
		"invalid bearer":     {path: "/api/v1/otp?format=html&fetch=1", headers: map[string]string{"Authorization": "Bearer nope"}},
		"invalid token":      {path: "/api/v1/otp?format=html&fetch=1&token=bogus"},
		"no credential":      {path: "/api/v1/otp?format=html&fetch=1"},
	} {
		t.Run(name, func(t *testing.T) {
			response := fixture.get(t, tc.path, tc.headers)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), otpFetchNotice) {
				t.Fatalf("fetch=1 body missing notice %q; body=%q", otpFetchNotice, response.Body.String())
			}
		})
	}
	for name, path := range map[string]string{
		"valid":           "/api/v1/otp?format=html&token=" + token,
		"invalid":         "/api/v1/otp?format=html&token=bogus",
		"fetch=2":         "/api/v1/otp?format=html&fetch=2&token=" + token,
		"duplicate fetch": "/api/v1/otp?format=html&fetch=1&fetch=1&token=" + token,
	} {
		t.Run("no notice "+name, func(t *testing.T) {
			if body := fixture.get(t, path, nil).Body.String(); strings.Contains(body, otpFetchNotice) {
				t.Fatalf("body shows the notice without a single fetch=1: %q", body)
			}
		})
	}
	valid := fixture.get(t, "/api/v1/otp?format=html&fetch=1", map[string]string{"Authorization": "Bearer " + fixture.emptyAPIKey})
	invalid := fixture.get(t, "/api/v1/otp?format=html&fetch=1", map[string]string{"Authorization": "Bearer nope"})
	if valid.Body.String() != invalid.Body.String() {
		t.Fatalf("fetch=1 pages differ\nvalid:   %q\ninvalid: %q", valid.Body.String(), invalid.Body.String())
	}
}

// TestOTPFormatHTMLFetchDoesNotSyncForInvalidCredentials pins ADR 0003: the
// button must not become a way to wake the syncer without a valid credential.
func TestOTPFormatHTMLFetchDoesNotSyncForInvalidCredentials(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	synced := make(chan int64, 4)
	fixture.env.server.sync = func(accountID int64) error {
		synced <- accountID
		return nil
	}
	for _, headers := range []map[string]string{
		nil,
		{"Authorization": "Bearer nope"},
	} {
		fixture.get(t, "/api/v1/otp?format=html&fetch=1&token=bogus", headers)
	}
	// Positive control: a valid request does wake the syncer, so an empty
	// channel above cannot be a broken hook.
	fixture.get(t, "/api/v1/otp?format=html&fetch=1&token="+url.QueryEscape(fixture.derived), nil)
	select {
	case <-synced:
	case <-time.After(2 * time.Second):
		t.Fatal("valid request did not trigger a sync")
	}
	select {
	case accountID := <-synced:
		t.Fatalf("an extra sync (account %d) ran; invalid credentials must not trigger one", accountID)
	case <-time.After(200 * time.Millisecond):
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
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+
		"&format=html&message="+strconv.FormatInt(fixture.messageID(t), 10), nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "MAIL_CONTENT_UNAVAILABLE") {
		t.Fatalf("body = %q; want MAIL_CONTENT_UNAVAILABLE", body)
	}
}

// TestOTPFormatHTMLReaderRejectsUnknownMessage keeps the archive row id from
// becoming a cross-alias lookup: the store scopes the query to the alias.
func TestOTPFormatHTMLReaderRejectsUnknownMessage(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+"&format=html&message=999999", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d; body=%q", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "MAIL_CONTENT_UNAVAILABLE") {
		t.Fatalf("body = %q; want MAIL_CONTENT_UNAVAILABLE", body)
	}
}

// TestOTPFormatHTMLReaderRejectsMessageFromAnotherAlias pins the alias scope:
// the message row exists, but it belongs to a sibling alias on the same
// account and therefore must not be readable with this alias's token.
func TestOTPFormatHTMLReaderRejectsMessageFromAnotherAlias(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	ctx := context.Background()
	aliases, err := fixture.env.store.ListAliases(ctx, fixture.accountID)
	if err != nil {
		t.Fatalf("list aliases: %v", err)
	}
	account, err := fixture.env.store.GetAccount(ctx, fixture.accountID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	received := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	rawMIME := []byte("Subject: Other alias mail\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Only the sibling alias may read this.\r\n")
	if err := fixture.env.store.ApplyMailboxSync(
		ctx,
		fixture.accountID,
		account.UpdatedAt,
		aliases,
		domain.MailboxSyncResult{
			ArchivedMessages: []domain.ArchivedMessage{{
				AccountID: fixture.accountID, UIDValidity: 91, UID: 2,
				InternalDate: received, Subject: "Other alias mail",
				RawMIME: rawMIME, OTP: "111111", AliasIDs: []int64{fixture.emptyAliasID},
			}},
			State: domain.IMAPSyncState{
				AccountID: fixture.accountID, UIDValidity: 91, LastUID: 2, UpdatedAt: received,
			},
			Reset: true,
		},
		received,
	); err != nil {
		t.Fatalf("archive sibling alias message: %v", err)
	}
	records, err := fixture.env.store.ListAliasOTPs(ctx, fixture.emptyAliasID, 10)
	if err != nil {
		t.Fatalf("list sibling alias OTPs: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("sibling alias records = %#v; want one", records)
	}
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+
		"&format=html&message="+strconv.FormatInt(records[0].MessageID, 10), nil)
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
	response := fixture.get(t, "/api/v1/otp?token="+url.QueryEscape(fixture.derived)+
		"&format=html&message="+strconv.FormatInt(fixture.messageID(t), 10), nil)
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
// sources intact while allowing exactly one format and the HTML-only message
// selector.
func TestOTPFormatQueryWhitelistRejectsEverythingElse(t *testing.T) {
	fixture := newOTPFormatEnv(t, "783448")
	token := url.QueryEscape(fixture.derived)
	for name, tc := range map[string]struct {
		path    string
		headers map[string]string
		html    bool
	}{
		"unknown parameter":      {path: "/api/v1/otp?token=" + token + "&next=elsewhere"},
		"invalid format":         {path: "/api/v1/otp?token=" + token + "&format=bogus"},
		"empty format":           {path: "/api/v1/otp?token=" + token + "&format="},
		"duplicate format":       {path: "/api/v1/otp?token=" + token + "&format=plain&format=html", html: true},
		"format without token":   {path: "/api/v1/otp?format=plain"},
		"duplicate token":        {path: "/api/v1/otp?token=" + token + "&token=" + token},
		"message without format": {path: "/api/v1/otp?token=" + token + "&message=1"},
		"message with plain":     {path: "/api/v1/otp?token=" + token + "&format=plain&message=1"},
		"empty message":          {path: "/api/v1/otp?token=" + token + "&format=html&message=", html: true},
		"non-numeric message":    {path: "/api/v1/otp?token=" + token + "&format=html&message=abc", html: true},
		"zero message":           {path: "/api/v1/otp?token=" + token + "&format=html&message=0", html: true},
		"negative message":       {path: "/api/v1/otp?token=" + token + "&format=html&message=-1", html: true},
		"duplicate message":      {path: "/api/v1/otp?token=" + token + "&format=html&message=1&message=2", html: true},
		"message without token":  {path: "/api/v1/otp?format=html&message=1", html: true},
		"fetch without format":   {path: "/api/v1/otp?token=" + token + "&fetch=1"},
		"fetch with plain":       {path: "/api/v1/otp?token=" + token + "&format=plain&fetch=1"},
		"fetch wrong value":      {path: "/api/v1/otp?token=" + token + "&format=html&fetch=2", html: true},
		"empty fetch":            {path: "/api/v1/otp?token=" + token + "&format=html&fetch=", html: true},
		"duplicate fetch":        {path: "/api/v1/otp?token=" + token + "&format=html&fetch=1&fetch=1", html: true},
		"format plus bearer": {
			path:    "/api/v1/otp?token=" + token + "&format=plain",
			headers: map[string]string{"Authorization": "Bearer " + fixture.credentials.APIKey},
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := serveV2Request(fixture.router, http.MethodGet, tc.path, "", tc.headers)
			if tc.html {
				body := response.Body.String()
				if response.Code != http.StatusOK || !strings.Contains(body, `<p class="alias">—</p>`) || strings.Contains(body, "<td") {
					t.Fatalf("status = %d; body=%q; want the empty inbox shell", response.Code, body)
				}
				return
			}
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
