import {
  buildOTPDirectLink,
  buildRecentMailDirectLink,
} from "./clipboard.js";

export const ALIAS_EXPORT_OTP = "otp";
export const ALIAS_EXPORT_OTP_HTML = "otp-html";
export const ALIAS_EXPORT_IMAP = "imap";
export const ALIAS_SALE_GROUP_NAME = "已卖";
export const ALIAS_SALE_BATCH_SIZE = 5;

function field(value, label) {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized || /[\r\n]/.test(normalized)) {
    throw new TypeError(`${label}格式无效。`);
  }
  return normalized;
}

export function buildAliasReceiveLink(
  alias,
  origin = globalThis.location?.origin,
) {
  const path =
    alias?.otpUrlPath || alias?.directLinkPath || alias?.legacyDirectLinkPath;
  return String(path || "").includes("/api/v1/otp")
    ? buildOTPDirectLink(path, origin)
    : buildRecentMailDirectLink(path, origin);
}

export function buildAliasExportLine(
  alias,
  format = ALIAS_EXPORT_OTP,
  origin = globalThis.location?.origin,
) {
  const address = field(alias?.address, "邮箱地址");
  if (format === ALIAS_EXPORT_OTP || format === ALIAS_EXPORT_OTP_HTML) {
    const link = buildAliasReceiveLink(alias, origin);
    if (format === ALIAS_EXPORT_OTP) {
      return `${address}-----${link}`;
    }
    let target;
    try {
      target = new URL(link);
    } catch {
      throw new TypeError("取码链接格式无效。");
    }
    if (target.pathname !== "/api/v1/otp") {
      throw new TypeError("取码链接格式无效。");
    }
    target.searchParams.set("format", "html");
    return `${address}-----${target.href}`;
  }
  if (format === ALIAS_EXPORT_IMAP) {
    return `${address}----${field(alias?.imapPassword, "IMAP 密码")}----${field(
      alias?.clientId,
      "client ID",
    )}----${field(alias?.refreshToken, "刷新令牌")}`;
  }
  throw new TypeError("邮箱复制格式无效。");
}

export function buildAliasExportText(
  aliases,
  format = ALIAS_EXPORT_OTP,
  origin = globalThis.location?.origin,
) {
  if (!Array.isArray(aliases)) {
    throw new TypeError("邮箱导出数据格式无效。");
  }

  return aliases
    .map((alias) => buildAliasExportLine(alias, format, origin))
    .join("\r\n");
}

export function selectAliasesForSale(aliases) {
  if (!Array.isArray(aliases)) {
    throw new TypeError("邮箱导出数据格式无效。");
  }

  return aliases
    .filter(
      (alias) =>
        alias?.enabled === true &&
        alias?.credentialMode !== "legacy" &&
        String(alias?.groupName || "").trim() !== ALIAS_SALE_GROUP_NAME &&
        String(alias?.otpUrlPath || "").startsWith("/api/v1/otp?"),
    )
    .slice(0, ALIAS_SALE_BATCH_SIZE);
}
