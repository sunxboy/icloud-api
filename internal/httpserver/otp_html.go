package httpserver

import (
	"bytes"
	"errors"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"icloud-api/internal/domain"
	"icloud-api/internal/mail"
	"icloud-api/internal/store"
)

// otpHTMLMessageLimit caps the inbox view. The archive keeps every message for
// the alias, so the HTML page needs a ceiling the JSON contracts do not.
const otpHTMLMessageLimit = 100

type otpInboxMessageView struct {
	Sender  string
	Subject string
	Time    string
	ReadURL string
}

type otpInboxView struct {
	Address  string
	Count    int
	FetchURL string
	Notice   bool
	Messages []otpInboxMessageView
}

type otpReaderView struct {
	BackURL string
	Subject string
	Sender  string
	Time    string
	Body    string
	HasBody bool
}

var otpInboxPage = template.Must(template.New("otp-inbox").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>邮件 ({{.Count}})</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f5f6f7;color:#1f2328;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif}
.page{max-width:1200px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}
.alias{color:#59636e;font-size:13px;margin:0;word-break:break-all}
.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 16px}
.fetch{flex:none;color:#fff;background:#0969da;text-decoration:none;padding:6px 14px;border-radius:6px}
.fetch:hover{background:#0550ae}
.notice{margin:-8px 0 16px;color:#59636e;font-size:13px}
.panel{background:#fff;border:1px solid #d8dee4;border-radius:8px;overflow:hidden}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid #eaeef2}
th{background:#f6f8fa;color:#59636e;font-weight:600;font-size:12px}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#f6f8fa}
.sender{width:30%;word-break:break-word}
.subject{word-break:break-word}
.time{width:150px;color:#59636e;white-space:nowrap}
.action{width:72px;text-align:center}
.read{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:6px;color:#0969da;text-decoration:none}
.read:hover{background:#ddf4ff}
.read svg{width:18px;height:18px}
@media (max-width:640px){.page{padding:12px}.sender{width:auto}.time{width:110px;font-size:12px}th,td{padding:10px}}
</style>
</head>
<body>
<div class="page">
<h1>邮件 ({{.Count}})</h1>
<div class="bar">
<p class="alias">{{.Address}}</p>
<a class="fetch" href="{{.FetchURL}}">收取邮件</a>
</div>
{{if .Notice}}<p class="notice">已请求收取，请稍后再次点击查看</p>
{{end}}<div class="panel">
<table>
<thead><tr><th class="sender">发件人</th><th class="subject">主题</th><th class="time">时间</th><th class="action">操作</th></tr></thead>
<tbody>
{{range .Messages}}<tr>
<td class="sender">{{.Sender}}</td>
<td class="subject">{{.Subject}}</td>
<td class="time">{{.Time}}</td>
<td class="action"><a class="read" href="{{.ReadURL}}" title="阅读" aria-label="阅读"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg></a></td>
</tr>{{end}}
</tbody>
</table>
</div>
</div>
</body>
</html>
`))

var otpReaderPage = template.Must(template.New("otp-reader").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Subject}}</title>
<style>
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:#f5f6f7;color:#1f2328;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif;display:flex;flex-direction:column}
.topbar{flex:none;min-height:56px;background:#fff;border-bottom:1px solid #d8dee4;padding:10px 16px;display:flex;align-items:center;gap:14px}
.back{flex:none;color:#0969da;text-decoration:none;padding:6px 10px;border-radius:6px}
.back:hover{background:#ddf4ff}
.meta{min-width:0}
.subject{margin:0;font-size:15px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.detail{margin:2px 0 0;color:#59636e;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.content{flex:1;min-height:0;padding:12px}
iframe{display:block;width:100%;height:100%;border:1px solid #d8dee4;border-radius:8px;background:#fff}
.empty{margin:0;padding:32px;text-align:center;color:#59636e;background:#fff;border:1px solid #d8dee4;border-radius:8px}
</style>
</head>
<body>
<header class="topbar">
{{if .BackURL}}<a class="back" href="{{.BackURL}}">← 返回列表</a>{{end}}
<div class="meta">
<h1 class="subject">{{.Subject}}</h1>
<p class="detail">{{.Sender}} · {{.Time}}</p>
</div>
</header>
<main class="content">
{{if .HasBody}}<iframe title="邮件正文" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation" referrerpolicy="no-referrer" srcdoc="{{.Body}}"></iframe>{{else}}<p class="empty">该邮件没有可读正文</p>{{end}}
</main>
</body>
</html>
`))

// writeOTPHTML renders the alias's inbox. No records still renders the page
// shell with the address masked, so it looks exactly like a rejected
// credential (ADR 0003).
func (s *Server) writeOTPHTML(c *gin.Context, binding domain.MailboxBinding) {
	messages, err := s.store.ListRecentArchivedMailboxMessages(c.Request.Context(), binding.Alias.ID, otpHTMLMessageLimit)
	if err != nil {
		s.logger.Error("读取归档邮件列表失败", "alias_id", binding.Alias.ID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return
	}
	view := newOTPInboxView(c)
	view.Count = len(messages)
	if len(messages) > 0 {
		view.Address = binding.Alias.Address
		view.Messages = make([]otpInboxMessageView, 0, len(messages))
	}
	for _, message := range messages {
		view.Messages = append(view.Messages, otpInboxMessageView{
			Sender:  formatMailAddresses(message.From),
			Subject: message.Subject,
			Time:    s.otpDisplayTime(message.InternalDate),
			ReadURL: otpHTMLURL(c, message.ID, false),
		})
	}
	s.writeOTPPage(c, otpInboxPage, view)
}

// writeOTPHTMLMessage renders one archived message behind a back bar. The
// sender's markup stays inside a sandboxed iframe: the bar is ours, so email
// CSS cannot restyle the page shell, and scripts stay disabled even though the
// email HTML itself is passed through verbatim.
func (s *Server) writeOTPHTMLMessage(c *gin.Context, aliasID, messageID int64) {
	c.Header("Content-Security-Policy", otpHTMLContentSecurityPolicy)
	message, err := s.store.GetArchivedMessageByID(c.Request.Context(), aliasID, messageID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeAPIError(c, http.StatusNotFound, "MAIL_CONTENT_UNAVAILABLE", "邮件正文不可用")
		return
	case err != nil:
		s.logger.Error("读取归档邮件失败", "alias_id", aliasID, "message_id", messageID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		return
	}
	bodies, err := s.archivedBodies(message)
	if err != nil {
		s.logger.Warn("邮件正文不可用", "alias_id", aliasID, "message_id", message.ID, "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusNotFound, "MAIL_CONTENT_UNAVAILABLE", "邮件正文不可用")
		return
	}
	body := renderEmailBody(bodies)
	subject := message.Subject
	if strings.TrimSpace(subject) == "" {
		subject = "(无主题)"
	}
	view := otpReaderView{
		Subject: subject,
		Sender:  formatMailAddresses(message.From),
		Time:    s.otpDisplayTime(message.InternalDate),
		Body:    body,
		HasBody: body != "",
	}
	if c.Query("token") != "" {
		view.BackURL = otpHTMLURL(c, 0, false)
	}
	s.writeOTPPage(c, otpReaderPage, view)
}

func (s *Server) writeOTPPage(c *gin.Context, page *template.Template, view any) {
	var output bytes.Buffer
	if err := page.Execute(&output, view); err != nil {
		s.logger.Error("渲染取码页面失败", "error", err, "request_id", requestID(c))
		s.writeAPIError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "服务内部错误")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", output.Bytes())
}

// otpInboxMaskedAddress stands in for the address whenever the inbox is empty,
// so a valid alias without mail and a rejected credential render identically.
const otpInboxMaskedAddress = "—"

// newOTPInboxView is the empty shell shared by every inbox response, so the
// rejected-credential page and the no-mail page cannot drift apart.
func newOTPInboxView(c *gin.Context) otpInboxView {
	return otpInboxView{
		Address:  otpInboxMaskedAddress,
		FetchURL: otpHTMLURL(c, 0, true),
		Notice:   otpFetchRequested(c.Request.URL.RawQuery),
	}
}

// otpHTMLURL rebuilds this endpoint's URL without the message parameter, or
// with it when messageID is positive; fetch adds the "收取邮件" parameter. The
// OTP token stays in the link because it is the only credential a browser can
// replay.
func otpHTMLURL(c *gin.Context, messageID int64, fetch bool) string {
	values := url.Values{}
	if token := c.Query("token"); token != "" {
		values.Set("token", token)
	}
	values.Set("format", "html")
	if messageID > 0 {
		values.Set("message", strconv.FormatInt(messageID, 10))
	}
	if fetch {
		values.Set("fetch", "1")
	}
	return c.Request.URL.Path + "?" + values.Encode()
}

func (s *Server) otpDisplayTime(value time.Time) string {
	location := s.cfg.Timezone
	if location == nil {
		location = time.Local
	}
	return value.In(location).Format("2006-01-02 15:04")
}

func formatMailAddresses(addresses []domain.MailAddress) string {
	parts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		switch {
		case address.Name != "" && address.Email != "":
			parts = append(parts, address.Name+" <"+address.Email+">")
		case address.Email != "":
			parts = append(parts, address.Email)
		case address.Name != "":
			parts = append(parts, address.Name)
		}
	}
	if len(parts) == 0 {
		return "未知发件人"
	}
	return strings.Join(parts, ", ")
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
