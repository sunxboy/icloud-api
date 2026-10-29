package httpserver

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"icloud-api/internal/domain"
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

// otpRequest is the parsed query contract of /api/v1/otp. messageID selects
// one archived message in the HTML format; it is never valid on its own.
type otpRequest struct {
	format    otpFormat
	messageID int64
}

// validateOTPQuery enforces the whole query contract of /api/v1/otp and
// returns the requested output shape. The endpoint is public, so an unknown
// parameter is rejected rather than ignored: otherwise the shape of a
// credential-bearing request would be negotiable.
func validateOTPQuery(values url.Values) (otpRequest, bool) {
	for key := range values {
		if key != "token" && key != "format" && key != "message" && key != "fetch" {
			return otpRequest{}, false
		}
	}
	request := otpRequest{format: otpFormatJSON}
	if requested := values["format"]; len(requested) > 1 {
		return otpRequest{}, false
	} else if len(requested) == 1 {
		switch format := otpFormat(requested[0]); format {
		case otpFormatPlain, otpFormatHTML:
			request.format = format
		default:
			return otpRequest{}, false
		}
	}
	if requested := values["message"]; len(requested) > 1 {
		return otpRequest{}, false
	} else if len(requested) == 1 {
		raw := requested[0]
		// The message selector only exists inside the HTML inbox. Accept ASCII
		// digits alone so "+1", " 1" and hex are rejected rather than coerced.
		if request.format != otpFormatHTML || raw == "" || strings.Trim(raw, "0123456789") != "" {
			return otpRequest{}, false
		}
		messageID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || messageID < 1 {
			return otpRequest{}, false
		}
		request.messageID = messageID
	}
	if requested := values["fetch"]; len(requested) > 1 {
		return otpRequest{}, false
	} else if len(requested) == 1 {
		// Like message, fetch only exists on the HTML inbox, and "1" is its
		// sole value so the link stays a fixed, non-negotiable shape.
		if request.format != otpFormatHTML || requested[0] != "1" {
			return otpRequest{}, false
		}
	}
	return request, true
}

// otpFetchRequested reports whether the raw query carries exactly one fetch=1.
// It reads the raw query rather than the validated request so the notice row
// shows up for rejected credentials too: its visibility must depend on the
// URL alone, never on whether the credential was accepted.
func otpFetchRequested(rawQuery string) bool {
	values, _ := url.ParseQuery(rawQuery)
	return len(values["fetch"]) == 1 && values["fetch"][0] == "1"
}

// otpWantsHTML reports whether the request asks for the browser-facing HTML
// shape. It deliberately inspects the raw query before validation: a malformed
// credential request that mentions format=html still gets the inbox shell
// instead of a JSON error.
func otpWantsHTML(rawQuery string) bool {
	values, _ := url.ParseQuery(rawQuery)
	for _, format := range values["format"] {
		if otpFormat(format) == otpFormatHTML {
			return true
		}
	}
	return false
}

// writeOTPAuthFailure keeps the JSON error contract for API clients while
// answering browser-facing HTML requests with the empty inbox shell. That page
// is identical to an alias with no archived mail, so scanners and stale links
// learn nothing about why the credential was rejected.
func (s *Server) writeOTPAuthFailure(c *gin.Context, htmlRequest bool, status int, code, message string) {
	if htmlRequest {
		s.writeOTPPage(c, otpInboxPage, newOTPInboxView(c))
		return
	}
	s.writeAPIError(c, status, code, message)
}

// otpHistory is deliberately a repeatable cache read. Neither authentication
// form consumes a code or changes upstream/local message flags.
func (s *Server) otpHistory(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	htmlRequest := otpWantsHTML(c.Request.URL.RawQuery)
	// Only invalid credentials consume this budget. A verified credential
	// refunds its reservation below, so normal polling never trips the limit;
	// checking first still keeps an invalid flood away from the store.
	limiterKey := c.ClientIP()
	if !s.otpInvalidLimiter.Allow(limiterKey) {
		s.writeOTPAuthFailure(c, htmlRequest, http.StatusTooManyRequests, "RATE_LIMITED", "请求过于频繁")
		return
	}
	binding, request, ok := s.authenticateOTPRequest(c, htmlRequest)
	if !ok {
		return
	}
	// OTP history is part of the v2 contract. Legacy aliases must continue to
	// use the original mailbox endpoints even if a stale credential bundle or
	// hash happens to remain on the row.
	if binding.Alias.CredentialMode != domain.AliasCredentialModeV2 ||
		!binding.Alias.Enabled || !binding.Account.Enabled {
		s.writeOTPAuthFailure(c, htmlRequest, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
		return
	}
	s.otpInvalidLimiter.Refund(limiterKey)
	now := time.Now().UTC()
	if s.now != nil {
		now = s.now().UTC()
	}
	s.requestMailboxSync(binding.Account.ID, now)
	if err := s.store.TouchAliasAccess(c.Request.Context(), binding.Alias.ID, now); err != nil {
		s.logger.Warn("更新 API 最近访问时间失败", "alias_id", binding.Alias.ID, "error", err, "request_id", requestID(c))
	}
	if request.format == otpFormatHTML {
		if request.messageID > 0 {
			s.writeOTPHTMLMessage(c, binding.Alias.ID, request.messageID)
		} else {
			s.writeOTPHTML(c, binding)
		}
		return
	}
	records, err := s.store.ListAliasOTPs(c.Request.Context(), binding.Alias.ID, 100)
	if err != nil {
		s.logger.Error("读取验证码归档失败", "alias_id", binding.Alias.ID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return
	}
	if request.format == otpFormatPlain {
		if len(records) == 0 {
			c.Data(http.StatusOK, "text/plain; charset=utf-8", nil)
			return
		}
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(records[0].OTP+"\n"))
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

func (s *Server) authenticateOTPRequest(c *gin.Context, htmlRequest bool) (domain.MailboxBinding, otpRequest, bool) {
	authorization := strings.TrimSpace(c.GetHeader("Authorization"))
	values, queryErr := url.ParseQuery(c.Request.URL.RawQuery)
	queryTokens := values["token"]
	queryPresent := len(queryTokens) > 0
	request, requestOK := validateOTPQuery(values)
	if queryErr != nil || len(queryTokens) > 1 || !requestOK || (authorization != "" && queryPresent) {
		s.writeOTPAuthFailure(c, htmlRequest, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
		return domain.MailboxBinding{}, otpRequest{}, false
	}

	var binding domain.MailboxBinding
	var err error
	if authorization != "" {
		scheme, token, found := strings.Cut(authorization, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || !validAPIKey(token) || strings.Contains(token, " ") {
			s.writeOTPAuthFailure(c, htmlRequest, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
			return domain.MailboxBinding{}, otpRequest{}, false
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
		s.writeOTPAuthFailure(c, htmlRequest, http.StatusUnauthorized, "INVALID_API_KEY", "API Key 无效")
		return domain.MailboxBinding{}, otpRequest{}, false
	}
	if err != nil {
		s.logger.Error("查询验证码凭证绑定失败", "error", err, "request_id", requestID(c))
		s.writeOTPAuthFailure(c, htmlRequest, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return domain.MailboxBinding{}, otpRequest{}, false
	}
	return binding, request, true
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
