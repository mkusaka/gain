import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { createJwt, isFresh, isGitHubHttps, listProfiles } from "./gain.ts";

test("createJwt signs a PKCS#1 key with valid claims", () => {
  // GitHub hands out PKCS#1 PEMs.
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const [h, p, sig] = createJwt("123", privateKey, 1000).split(".");
  assert.ok(
    verify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig, "base64url")),
  );
  assert.deepEqual(JSON.parse(Buffer.from(p, "base64url").toString()), {
    iat: 940,
    exp: 1540,
    iss: "123",
  });
});

test("isFresh requires more than five minutes of validity", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  assert.equal(isFresh({ token: "t", expires_at: "2026-01-01T00:10:00Z" }, now), true);
  assert.equal(isFresh({ token: "t", expires_at: "2026-01-01T00:04:00Z" }, now), false);
  assert.equal(isFresh(undefined, now), false);
});

test("isGitHubHttps only matches https://github.com", () => {
  assert.equal(isGitHubHttps("protocol=https\nhost=github.com\npath=org/repo.git\n"), true);
  assert.equal(isGitHubHttps("protocol=http\nhost=github.com\n"), false);
  assert.equal(isGitHubHttps("protocol=https\nhost=github.com.evil.example\n"), false);
  assert.equal(isGitHubHttps("protocol=https\nhost=gitlab.com\n"), false);
});

test("listProfiles picks config items of the gain service only", () => {
  const item = (svce: string, acct: string) =>
    `keychain: "/x/login.keychain-db"\nclass: "genp"\nattributes:\n    "acct"<blob>="${acct}"\n    "svce"<blob>="${svce}"\n`;
  const dump = [
    item("gain", "token:work"),
    item("gain", "config:work"),
    item("gain", "config:default"),
    item("other", "config:nope"),
  ].join("");
  assert.deepEqual(listProfiles(dump), ["default", "work"]);
});
