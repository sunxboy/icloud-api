# 取码接口的 HTML 形态改为归档邮件列表 + 沙箱阅读页

`GET /api/v1/otp?format=html` 原本只原样返回最新验证码邮件的正文。现在它需要先展示该隐私邮箱的归档邮件列表（发件人、主题、时间、操作），再由用户点开其中一封阅读。

ADR 0001 决定不净化邮件 HTML，这一条继续成立：阅读页仍按原字节渲染发信人提供的 HTML，图片与按钮照常工作。被取代的是它对「`sandbox` iframe 包裹」的拒绝。列表页引入了一个属于服务自己的返回栏，如果让不可信的邮件 HTML 直接进入页面 DOM，邮件里的 `body`/`*` 样式可以盖住或伪造返回栏和标题。阅读页因此把正文放进 `iframe srcdoc`：

- 保留 `sandbox="allow-same-origin"` 让相对链接与图片仍能按原域解析；
- 不给出 `allow-scripts`，邮件脚本始终不执行（与 `script-src 'self'` 叠加）；
- 允许 `allow-popups`、`allow-popups-to-escape-sandbox` 与 `allow-top-navigation-by-user-activation`，使邮件里的链接在用户点击后仍能正常打开；
- 阅读页继续使用放宽了 `img-src` 的 CSP，列表页则留在全局严格 CSP 上。

没有邮件时 `format=html` 仍是 `200` + 零字节响应体；`format=html&message=<id>` 必须指向当前隐私邮箱的归档邮件，正文不可读或越权都返回 `404 MAIL_CONTENT_UNAVAILABLE`。列表最新优先、最多 100 封，包含没有提取到验证码的邮件。

## Consequences

邮件正文现在被隔离在 iframe 中，正文里的相对链接与锚点在 iframe 内解析，而不是替换整个取码页面；这是为保住返回栏和列表状态而接受的差异。阅读页的 `srcdoc` 必须继续按字节转义并保持无 `allow-scripts`，测试会同时固定这两点。

## Status

已接受，2026-10-21。取代 ADR 0001 中关于 `sandbox` iframe 的取舍，保留其「不净化邮件 HTML」的核心决定。
