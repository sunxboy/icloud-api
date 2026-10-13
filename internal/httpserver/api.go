package httpserver

import (
	"errors"
	"html"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"icloud-api/internal/domain"
	"icloud-api/internal/mail"
	"icloud-api/internal/secure"
	"icloud-api/internal/store"
)

type otpResponse struct {
	OTP  string `json:"otp"`
	Time string `json:"time"`
}

// otpFormat is the requested /api/v1/otp output shape. The zero value keeps the
// original JSON contract, which existing callers depend on.
type otpFormat string

const (
	otpFormatJSON  otpFormat = ""
	otpFormatPlain otpFormat = "plain"
	otpFormatHTML  otpFormat = "html"
)

// validateOTPQuery enforces the whole query contract of /api/v1/otp and
// returns the requested output format. The endpoint is public, so an unknown
// parameter is rejected rather than ignored: otherwise the shape of a
// credential-bearing request would be negotiable.
func validateOTPQuery(values url.Values) (otpFormat, bool) {
	for key := range values {
		if key != "token" && key != "format" {
			return otpFormatJSON, false
		}
	}
	requested := values["format"]
	if len(requested) > 1 {
		return otpFormatJSON, false
	}
	if len(requested) == 0 {
		return otpFormatJSON, true
	}
	switch format := otpFormat(requested[0]); format {
	case otpFormatPlain, otpFormatHTML:
		return format, true
	default:
		return otpFormatJSON, false
	}
}

// otpHistory is deliberately a repeatable cache read. Neither authentication
// form consumes a code or changes upstream/local message flags.
func (s *Server) otpHistory(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	binding, format, ok := s.authenticateOTPRequest(c)
	if !ok {
		return
	}
	// OTP history is part of the v2 contract. Legacy aliases must continue to
	// use the original mailbox endpoints even if a stale credential bundle or
	// hash happens to remain on the row.
	if binding.Alias.CredentialMode != domain.AliasCredentialModeV2 ||
		!binding.Alias.Enabled || !binding.Account.Enabled {
		s.writeAPIError(c, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
		return
	}
	now := time.Now().UTC()
	if s.now != nil {
		now = s.now().UTC()
	}
	s.requestMailboxSync(binding.Account.ID, now)
	if err := s.store.TouchAliasAccess(c.Request.Context(), binding.Alias.ID, now); err != nil {
		s.logger.Warn("更新 API 最近访问时间失败", "alias_id", binding.Alias.ID, "error", err, "request_id", requestID(c))
	}
	records, err := s.store.ListAliasOTPs(c.Request.Context(), binding.Alias.ID, 100)
	if err != nil {
		s.logger.Error("读取验证码归档失败", "alias_id", binding.Alias.ID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return
	}
	switch format {
	case otpFormatPlain:
		if len(records) == 0 {
			c.Data(http.StatusOK, "text/plain; charset=utf-8", nil)
			return
		}
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(records[0].OTP+"\n"))
		return
	case otpFormatHTML:
		s.writeOTPHTML(c, binding.Alias.ID, records)
		return
	}
	location := s.cfg.Timezone
	if location == nil {
		location = time.Local
	}
	result := make([]otpResponse, 0, len(records))
	for _, record := range records {
		result = append(result, otpResponse{OTP: record.OTP, Time: record.Time.In(location).Format(time.RFC3339)})
	}
	if s.cfg.OTPReturnLatestOnly && len(result) > 0 {
		c.JSON(http.StatusOK, result[0])
		return
	}
	c.JSON(http.StatusOK, result)
}

// writeOTPHTML renders the body of the newest OTP message. HTML the sender
// provided is passed through verbatim; the caller opted into seeing third-party
// markup, so the bytes are not rewritten and the response instead carries a CSP
// that keeps archived HTML from running scripts or hijacking links.
//
// No records is the alias's normal empty state and stays blank. A message that
// exists but whose archive body cannot be read is reported as an error instead:
// a blank page there would hide an eviction or a corrupt archive behind the
// same response as "no mail yet".
func (s *Server) writeOTPHTML(c *gin.Context, aliasID int64, records []domain.OTPRecord) {
	c.Header("Content-Security-Policy", otpHTMLContentSecurityPolicy)
	if len(records) == 0 {
		c.Data(http.StatusOK, "text/html; charset=utf-8", nil)
		return
	}
	message, err := s.store.GetArchivedMessageByID(c.Request.Context(), aliasID, records[0].MessageID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeAPIError(c, http.StatusNotFound, "MAIL_CONTENT_UNAVAILABLE", "邮件正文不可用")
		return
	case err != nil:
		s.logger.Error("读取验证码邮件失败", "alias_id", aliasID, "message_id", records[0].MessageID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return
	}
	bodies, err := s.archivedBodies(message)
	if err != nil {
		s.logger.Warn("验证码邮件正文不可用", "alias_id", aliasID, "message_id", message.ID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusNotFound, "MAIL_CONTENT_UNAVAILABLE", "邮件正文不可用")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(renderEmailBody(bodies)))
}

// archivedBodies reads the archived raw MIME and re-parses its readable parts.
// Every failure here says the same thing to the caller — the archived body
// cannot be shown — so it collapses to one error instead of separating an
// eviction from a checksum mismatch. The IMAPS path treats both as the same
// explanatory placeholder for the same reason.
func (s *Server) archivedBodies(message domain.ArchivedMailboxMessage) (mail.ReadableBodies, error) {
	content, err := s.store.OpenArchivedContent(message)
	if err != nil {
		return mail.ReadableBodies{}, err
	}
	defer content.Close()
	return mail.BodiesFromMIME(content, message.ContentBytes, s.cfg.MaxBodyBytes)
}

// renderEmailBody shows whichever body the sender provided, preferring HTML.
// A plain-text-only message is shown as text rather than as a blank page:
// escaping it into a <pre> keeps the line breaks the sender wrote, and the
// escaping stops that text from being interpreted as markup. Only a message
// with no readable body at all renders blank.
func renderEmailBody(bodies mail.ReadableBodies) string {
	if strings.TrimSpace(bodies.HTML) != "" {
		return bodies.HTML
	}
	if strings.TrimSpace(bodies.Text) == "" {
		return ""
	}
	return "<pre>" + html.EscapeString(bodies.Text) + "</pre>"
}

func (s *Server) authenticateOTPRequest(c *gin.Context) (domain.MailboxBinding, otpFormat, bool) {
	authorization := strings.TrimSpace(c.GetHeader("Authorization"))
	values, queryErr := url.ParseQuery(c.Request.URL.RawQuery)
	queryTokens := values["token"]
	queryPresent := len(queryTokens) > 0
	format, formatOK := validateOTPQuery(values)
	if queryErr != nil || len(queryTokens) > 1 || !formatOK || (authorization != "" && queryPresent) {
		s.writeAPIError(c, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
		return domain.MailboxBinding{}, otpFormatJSON, false
	}

	var binding domain.MailboxBinding
	var err error
	if authorization != "" {
		scheme, token, found := strings.Cut(authorization, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || !validAPIKey(token) || strings.Contains(token, " ") {
			s.writeAPIError(c, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
			return domain.MailboxBinding{}, otpFormatJSON, false
		}
		binding, err = s.store.GetMailboxBindingByAPIKeyHash(c.Request.Context(), secure.HashToken(token))
	} else if len(queryTokens) == 1 && validAPIKey(queryTokens[0]) {
		token := queryTokens[0]
		aliasID, candidate := secure.OTPTokenAliasID(token)
		if !candidate {
			err = store.ErrNotFound
		} else {
			alias, lookupErr := s.store.GetAlias(c.Request.Context(), aliasID)
			switch {
			case lookupErr != nil:
				err = lookupErr
			case !s.cipher.VerifyOTPToken(token, aliasID, alias.APIKeyHash):
				err = store.ErrNotFound
			default:
				binding, err = s.store.GetMailboxBindingByAPIKeyHash(c.Request.Context(), alias.APIKeyHash)
			}
		}
	} else {
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		s.writeAPIError(c, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
		return domain.MailboxBinding{}, otpFormatJSON, false
	}
	if err != nil {
		s.logger.Error("查询验证码凭证绑定失败", "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return domain.MailboxBinding{}, otpFormatJSON, false
	}
	return binding, format, true
}

func (s *Server) issueIMAPAccessToken(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	if !s.externalAPILimiter.Allow(c.ClientIP()) {
		writeOAuthError(c, http.StatusTooManyRequests, "temporarily_unavailable", "请求过于频繁")
		return
	}
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || c.Request.URL.RawQuery != "" {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request", "请求必须使用表单编码")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	if err := c.Request.ParseForm(); err != nil {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request", "请求表单无效")
		return
	}
	clientIDs := c.Request.PostForm["client_id"]
	refreshTokens := c.Request.PostForm["refresh_token"]
	grantTypes := c.Request.PostForm["grant_type"]
	if len(clientIDs) != 1 || len(refreshTokens) != 1 || len(grantTypes) != 1 ||
		grantTypes[0] != "refresh_token" || len(c.Request.PostForm) != 3 {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request", "client_id、refresh_token 和 grant_type 必须各出现一次")
		return
	}
	clientID := strings.TrimSpace(clientIDs[0])
	refreshToken := refreshTokens[0]
	if clientID == "" || refreshToken == "" || strings.TrimSpace(refreshToken) != refreshToken ||
		strings.ContainsAny(clientID+refreshToken, " \t\r\n") {
		writeOAuthError(c, http.StatusUnauthorized, "invalid_client", "客户端凭证无效")
		return
	}
	binding, err := s.store.GetMailboxBindingByOAuthClientID(c.Request.Context(), clientID)
	if errors.Is(err, store.ErrNotFound) || err == nil &&
		(binding.Alias.CredentialMode != domain.AliasCredentialModeV2 ||
			!binding.Alias.Enabled || !binding.Account.Enabled ||
			!secure.HashEqual(binding.Alias.RefreshTokenHash, secure.HashToken(refreshToken))) {
		writeOAuthError(c, http.StatusUnauthorized, "invalid_client", "客户端凭证无效")
		return
	}
	if err != nil {
		s.logger.Error("查询令牌凭证失败", "error", err, "request_id", requestID(c))
		writeOAuthError(c, http.StatusServiceUnavailable, "temporarily_unavailable", "令牌服务暂不可用")
		return
	}
	now := time.Now().UTC()
	if s.now != nil {
		now = s.now().UTC()
	}
	const lifetime = time.Hour
	accessToken, err := s.cipher.IssueAliasAccessToken(
		binding.Alias.ID,
		binding.Alias.CredentialVersion,
		binding.Alias.RefreshTokenHash,
		now.Add(lifetime),
	)
	if err != nil {
		s.logger.Error("签发 IMAPS 访问令牌失败", "error", err, "request_id", requestID(c))
		writeOAuthError(c, http.StatusServiceUnavailable, "temporarily_unavailable", "令牌服务暂不可用")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(lifetime.Seconds()),
	})
}

func writeOAuthError(c *gin.Context, status int, code, description string) {
	c.JSON(status, gin.H{"error": code, "error_description": description})
}
