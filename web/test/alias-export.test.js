import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ALIAS_EXPORT_IMAP,
  ALIAS_EXPORT_OTP,
  ALIAS_EXPORT_OTP_HTML,
  buildAliasReceiveLink,
  buildAliasExportText,
  selectAliasesForSale,
} from "../src/utils/aliasExport.js";

const aliasesViewPath = new URL("../src/views/AliasesView.vue", import.meta.url);

function functionBody(source, signature) {
  const start = source.indexOf(signature);
  assert.notEqual(start, -1, `missing ${signature}`);
  const opening = source.indexOf("{", start);
  assert.notEqual(opening, -1, `missing body for ${signature}`);
  let depth = 0;
  for (let index = opening; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(opening, index + 1);
    }
  }
  assert.fail(`unterminated body for ${signature}`);
}

test("OTP export uses five hyphens, absolute links, one line per alias, and no header", () => {
  const exported = buildAliasExportText(
    [
      {
        address: "first@icloud.com",
        otpUrlPath: "/api/v1/otp?token=first-token",
      },
      {
        address: "second@icloud.com",
        otpUrlPath: "/api/v1/otp?token=second%2Btoken",
      },
    ],
    ALIAS_EXPORT_OTP,
    "https://mail.example.test:8443",
  );

  assert.equal(
    exported,
    [
      "first@icloud.com-----https://mail.example.test:8443/api/v1/otp?token=first-token",
      "second@icloud.com-----https://mail.example.test:8443/api/v1/otp?token=second%2Btoken",
    ].join("\r\n"),
  );
});

test("sell export appends format=html to each OTP link", () => {
  const exported = buildAliasExportText(
    [
      {
        address: "34_naval.callas@icloud.com",
        otpUrlPath: "/api/v1/otp?token=icm_example",
      },
    ],
    ALIAS_EXPORT_OTP_HTML,
    "http://127.0.0.1:8083",
  );

  assert.equal(
    exported,
    "34_naval.callas@icloud.com-----http://127.0.0.1:8083/api/v1/otp?token=icm_example&format=html",
  );
});

test("sell export rejects legacy direct links", () => {
  assert.throws(
    () =>
      buildAliasExportText(
        [
          {
            address: "legacy@icloud.com",
            directLinkPath: "/api/v1/mail/recent?api_key=legacy",
          },
        ],
        ALIAS_EXPORT_OTP_HTML,
        "https://mail.example.test",
      ),
    /取码链接格式无效/,
  );
});

test("sale selection skips sold, disabled, legacy, and missing OTP links and caps at five", () => {
  const aliases = Array.from({ length: 7 }, (_, index) => ({
    id: index + 1,
    address: `mail-${index + 1}@icloud.com`,
    enabled: true,
    credentialMode: "v2",
    groupName: "",
    otpUrlPath: `/api/v1/otp?token=token-${index + 1}`,
  }));
  aliases[0].groupName = "已卖";
  aliases[1].enabled = false;
  aliases[2].credentialMode = "legacy";
  aliases[3].otpUrlPath = "";

  assert.deepEqual(
    selectAliasesForSale(aliases).map((alias) => alias.id),
    [5, 6, 7],
  );

  const enough = Array.from({ length: 8 }, (_, index) => ({
    id: index + 1,
    enabled: true,
    credentialMode: "v2",
    groupName: "",
    otpUrlPath: `/api/v1/otp?token=token-${index + 1}`,
  }));
  assert.deepEqual(
    selectAliasesForSale(enough).map((alias) => alias.id),
    [1, 2, 3, 4, 5],
  );
});

test("receive links open the OTP endpoint and keep legacy aliases compatible", () => {
  assert.equal(
    buildAliasReceiveLink(
      { otpUrlPath: "/api/v1/otp?token=derived-token" },
      "https://mail.example.test:8443",
    ),
    "https://mail.example.test:8443/api/v1/otp?token=derived-token",
  );
  assert.equal(
    buildAliasReceiveLink(
      { directLinkPath: "/api/v1/mail/recent?api_key=legacy-token" },
      "https://mail.example.test:8443",
    ),
    "https://mail.example.test:8443/api/v1/mail/recent?api_key=legacy-token",
  );
  assert.equal(
    buildAliasReceiveLink(
      {
        legacyDirectLinkPath:
          "/api/v1/mail/recent?api_key=legacy-fallback-token",
      },
      "https://mail.example.test:8443",
    ),
    "https://mail.example.test:8443/api/v1/mail/recent?api_key=legacy-fallback-token",
  );
});

test("IMAP export uses four hyphens and preserves requested alias order", () => {
  const exported = buildAliasExportText(
    [
      {
        address: "z-last@icloud.com",
        imapPassword: "imap-z",
        clientId: "client-z",
        refreshToken: "refresh-z",
      },
      {
        address: "a-first@icloud.com",
        imapPassword: "imap-a",
        clientId: "client-a",
        refreshToken: "refresh-a",
      },
    ],
    ALIAS_EXPORT_IMAP,
  );

  assert.equal(
    exported,
    [
      "z-last@icloud.com----imap-z----client-z----refresh-z",
      "a-first@icloud.com----imap-a----client-a----refresh-a",
    ].join("\r\n"),
  );
});

test("credential export rejects missing fields, injected lines, and foreign OTP links", () => {
  assert.throws(
    () =>
      buildAliasExportText(
        [{ address: "", otpUrlPath: "/api/v1/otp?token=token" }],
        ALIAS_EXPORT_OTP,
        "https://mail.example.test",
      ),
    /邮箱地址格式无效/,
  );
  assert.throws(
    () =>
      buildAliasExportText(
        [
          {
            address: "private@icloud.com",
            otpUrlPath: "https://attacker.example/api/v1/otp?token=token",
          },
        ],
        ALIAS_EXPORT_OTP,
        "https://mail.example.test",
      ),
    /链接格式无效/,
  );
  assert.throws(
    () =>
      buildAliasExportText(
        [
          {
            address: "private@icloud.com",
            imapPassword: "imap\npassword",
            clientId: "client",
            refreshToken: "refresh",
          },
        ],
        ALIAS_EXPORT_IMAP,
      ),
    /IMAP 密码格式无效/,
  );
});

test("all aliases view hides credential fields and supports single, checked, and all copy", async () => {
  const source = await readFile(aliasesViewPath, "utf8");
  const exportableBody = functionBody(source, "function isAliasExportable");
  const isAliasExportable = Function(
    `"use strict"; return function (alias) ${exportableBody}`,
  )();
  const complete = {
    address: "private@icloud.com",
    apiKey: "api-key",
    imapPassword: "imap-password",
    clientId: "client-id",
    refreshToken: "refresh-token",
    otpUrlPath: "/api/v1/otp?token=derived",
  };

  assert.equal(isAliasExportable(complete), true);
  assert.equal(isAliasExportable({ ...complete, refreshToken: "" }), false);
  for (const field of ["apiKey", "imapPassword", "clientId", "refreshToken"]) {
    assert.doesNotMatch(
      source,
      new RegExp(`\\{\\{ (?:row|alias)\\.${field} \\}\\}`),
    );
  }
  for (const label of ["API Key", "IMAP 密码", "client ID", "刷新令牌"]) {
    assert.doesNotMatch(source, new RegExp(`<(?:dt|th)[^>]*>\\s*${label}`));
  }
  assert.match(source, /copyAliasLine\(row, ALIAS_EXPORT_OTP\)/);
  assert.match(source, /copyAliasLine\(row, ALIAS_EXPORT_IMAP\)/);
  assert.match(source, /@click="openAliasInbox\(row\)"/);
  assert.match(source, /@click="openAliasInbox\(alias\)"/);
  assert.match(
    functionBody(source, "function isAliasReceiveAvailable"),
    /!isAliasConfirmationPending\(alias\)/,
  );
  assert.match(
    functionBody(source, "function openAliasInbox"),
    /window\.open\([\s\S]*buildAliasReceiveLink\(alias\)[\s\S]*"_blank"[\s\S]*"noopener,noreferrer"/,
  );
  assert.match(source, /copySelectedAliases\(ALIAS_EXPORT_OTP\)/);
  assert.match(source, /copySelectedAliases\(ALIAS_EXPORT_IMAP\)/);
  assert.match(source, /copyAllAliases\(ALIAS_EXPORT_OTP\)/);
  assert.match(source, /copyAllAliases\(ALIAS_EXPORT_IMAP\)/);
  assert.match(
    functionBody(source, "function copyAllAliases"),
    /getAllAliases\(selectedAccountId\.value,\s*\{[\s\S]*query:\s*appliedAliasQuery\.value[\s\S]*withoutLatestMail:\s*withoutLatestMail\.value[\s\S]*withLatestMail:\s*withLatestMail\.value/,
  );
});

test("all aliases view displays custom account suffixes without the internal placeholder", async () => {
  const source = await readFile(aliasesViewPath, "utf8");
  const identityBody = functionBody(source, "function formatAccountIdentity");
  const formatAccountIdentity = Function(
    `"use strict"; return function (account) ${identityBody}`,
  )();

  assert.equal(
    formatAccountIdentity({
      email: "custom@example.test",
      mailboxType: "custom",
      emailSuffix: "example.test",
    }),
    "@example.test",
  );
  assert.equal(
    formatAccountIdentity({
      email: "primary@icloud.com",
      mailboxType: "icloud",
      emailSuffix: "",
    }),
    "primary@icloud.com",
  );
  assert.equal(
    formatAccountIdentity({ accountEmail: "custom@fallback.test" }),
    "@fallback.test",
  );
  assert.match(source, /:label="formatAccountIdentity\(account\)"/);
  assert.match(source, /\{\{ formatAccountIdentity\(account\) \}\}/);
  assert.match(source, /\{\{ formatAliasAccountIdentity\(row\) \|\| "查看主号" \}\}/);
  assert.match(source, /\{\{ formatAliasAccountIdentity\(alias\) \|\| "-" \}\}/);
});
