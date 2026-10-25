import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parse } from "@optique/core/parser";
import {
  Agent,
  createJwt,
  deriveKey,
  isFresh,
  isGitHubHttps,
  launchdPlist,
  listProfiles,
  parser,
  pickInstallation,
  seal,
  unseal,
} from "./gain.ts";

test("vault round-trips and rejects a wrong passphrase", () => {
  const salt = randomBytes(16);
  const config = { clientId: "c", installationId: "1", privateKey: "pem" };
  const { data } = JSON.parse(seal(deriveKey("right", salt), salt, new Map([["w", config]])));
  const blob = Buffer.from(data, "base64");
  assert.deepEqual(unseal(deriveKey("right", salt), blob), new Map([["w", config]]));
  assert.throws(() => unseal(deriveKey("wrong", salt), blob), /wrong passphrase/);
});

test("agent creates the vault on first unlock and gates everything behind it", async () => {
  const vault = join(mkdtempSync(join(tmpdir(), "gain-")), "vault");
  const agent = new Agent(vault);
  assert.deepEqual(await agent.handle({ cmd: "status" }), { unlocked: false });
  await assert.rejects(agent.handle({ cmd: "list" }), /locked/);
  await agent.handle({ cmd: "unlock", passphrase: "pass" });
  assert.equal(statSync(vault).mode & 0o777, 0o600);
  assert.ok(!readFileSync(vault, "utf8").includes("pem"));
  assert.deepEqual(await agent.handle({ cmd: "list" }), { profiles: [] });
  await assert.rejects(agent.handle({ cmd: "token", profile: "x" }), /not configured/);
  await assert.rejects(agent.handle({ cmd: "token", profile: "../x" }), /profile names/);
  await agent.handle({ cmd: "lock" });
  assert.equal(agent.key, undefined);
  await assert.rejects(agent.handle({ cmd: "unlock", passphrase: "nope" }), /wrong passphrase/);
  await agent.handle({ cmd: "unlock", passphrase: "pass" });
  assert.deepEqual(await agent.handle({ cmd: "status" }), { unlocked: true });
});

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

test("isFresh requires more than minTtl minutes of validity (default 5)", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  assert.equal(isFresh({ token: "t", expires_at: "2026-01-01T00:10:00Z" }, undefined, now), true);
  assert.equal(isFresh({ token: "t", expires_at: "2026-01-01T00:04:00Z" }, undefined, now), false);
  assert.equal(isFresh({ token: "t", expires_at: "2026-01-01T00:29:00Z" }, 30, now), false);
  assert.equal(isFresh({ token: "t", expires_at: "2026-01-01T00:31:00Z" }, 30, now), true);
  assert.equal(isFresh(undefined, 5, now), false);
});

test("isGitHubHttps only matches https://github.com", () => {
  assert.equal(isGitHubHttps("protocol=https\nhost=github.com\npath=org/repo.git\n"), true);
  assert.equal(isGitHubHttps("protocol=http\nhost=github.com\n"), false);
  assert.equal(isGitHubHttps("protocol=https\nhost=github.com.evil.example\n"), false);
  assert.equal(isGitHubHttps("protocol=https\nhost=gitlab.com\n"), false);
});

test("listProfiles picks gain <= 0.3 Keychain config items only", () => {
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

test("launchdPlist escapes paths", () => {
  const xml = launchdPlist(["/a&b/bun", "/x<y/gain.js"], "/l.log");
  assert.ok(xml.includes("<string>/a&amp;b/bun</string><string>/x&lt;y/gain.js</string>"));
});

test("pickInstallation uses the only installation, otherwise asks", () => {
  const inst = (id: number, login: string) => ({ id, account: { login } });
  assert.equal(pickInstallation([inst(42, "org")]), "42");
  assert.throws(() => pickInstallation([]), /not installed/);
  assert.throws(() => pickInstallation([inst(1, "a"), inst(2, "b")]), /1 \(a\), 2 \(b\)/);
});

test("parser passes non-gain args to gh untouched and bounds --min-ttl", () => {
  delete process.env.GH_APP_PROFILE; // the profile default reads it
  const value = (args: string[]) => {
    const r = parse(parser, args);
    return r.success ? r.value : undefined;
  };
  assert.deepEqual(value(["--profile", "w", "api", "x", "--jq", ".a", "--help"]), {
    profile: "w",
    cmd: { action: "gh", args: ["api", "x", "--jq", ".a", "--help"] },
  });
  assert.deepEqual(value([]), { profile: "default", cmd: { action: "gh", args: [] } });
  assert.deepEqual(value(["token", "--min-ttl", "30"]), {
    profile: "default",
    cmd: { action: "token", minTtl: 30 },
  });
  assert.equal(value(["token", "--min-ttl", "61"]), undefined);
  assert.deepEqual(value(["profile", "remove", "w"]), { action: "profile remove", name: "w" });
  assert.deepEqual(value(["revoke"]), { profile: "default", cmd: { action: "revoke" } });
  assert.deepEqual(value(["agent", "unlock"]), { action: "agent", op: "unlock" });
  assert.equal(value(["agent", "dump"]), undefined);
});
