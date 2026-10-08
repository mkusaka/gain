#!/usr/bin/env node
// Run `gh` with a GitHub App installation token in GH_TOKEN. Runs on Node (>=24.2) or Bun, macOS only.
// Usage: gain [--profile NAME] setup --app-id ID --installation-id ID --private-key-path FILE   (stores in macOS Keychain)
//        gain [--profile NAME] <gh args...>   e.g. gain --profile work pr list -R org/repo
//        gain [--profile NAME] token          print the token (for curl, scripts, ...)
//        gain [--profile NAME] credential get git credential helper (see README)
// Profile defaults to $GH_APP_PROFILE, then "default".
import { spawnSync } from "node:child_process";
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { constants } from "node:os";
import { parseArgs } from "node:util";

type Config = { appId: string; installationId: string; privateKey: string };
type Cached = { token: string; expires_at: string };

const SERVICE = "gain";
const SETUP_USAGE =
  "gain [--profile NAME] setup --app-id ID --installation-id ID --private-key-path FILE";

// macOS Keychain via the `security` CLI. Values are written through stdin (`security -i`) so
// secrets never appear in argv / `ps`, base64-encoded so they need no quoting.
// ponytail: `security -i` splits lines at 4095 chars, which fits GitHub's 2048-bit App keys
// (~2.4k) but not 4096-bit ones; chunk across items if bigger keys ever matter.
const secret = {
  get<T>(name: string): T | undefined {
    const r = spawnSync("security", ["find-generic-password", "-s", SERVICE, "-a", name, "-w"], {
      encoding: "utf8",
    });
    if (r.status === 44) return undefined; // not found
    if (r.status !== 0) throw new Error(`keychain read failed: ${r.stderr || r.error}`);
    return JSON.parse(Buffer.from(r.stdout.trim(), "base64").toString());
  },
  set(name: string, value: unknown) {
    const b64 = Buffer.from(JSON.stringify(value)).toString("base64");
    const line = `add-generic-password -U -s ${SERVICE} -a ${name} -w ${b64}\n`;
    if (line.length > 4000) throw new Error(`value for "${name}" is too large for the Keychain`);
    const r = spawnSync("security", ["-i"], { input: line, encoding: "utf8" });
    // Don't echo stderr: on a parse error `security` repeats the (secret) input.
    if (r.status !== 0 || r.stderr) throw new Error(`keychain write failed for "${name}"`);
  },
};

const b64url = (s: string | Buffer) => Buffer.from(s).toString("base64url");

export function createJwt(
  appId: string,
  privateKey: string,
  now = Math.floor(Date.now() / 1000),
): string {
  // GitHub rejects exp more than 10 minutes out; iat is backdated for clock skew.
  const body = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64url(
    JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }),
  )}`;
  return `${body}.${createSign("RSA-SHA256").update(body).sign(privateKey, "base64url")}`;
}

// 5 minutes of headroom so long-running commands (e.g. `gh run watch`) don't outlive the token.
export const isFresh = (c: Cached | undefined, now = Date.now()) =>
  !!c && Date.parse(c.expires_at) - now > 5 * 60_000;

// git credential protocol: key=value lines on stdin. Only answer for https://github.com.
export function isGitHubHttps(request: string): boolean {
  const fields = Object.fromEntries(
    request.split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );
  return fields.protocol === "https" && fields.host === "github.com";
}

async function fetchToken({ appId, installationId, privateKey }: Config): Promise<Cached> {
  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${createJwt(appId, privateKey)}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gain",
      },
    },
  );
  if (!res.ok) throw new Error(`token request failed: ${res.status} ${await res.text()}`);
  const { token, expires_at } = (await res.json()) as Cached;
  return { token, expires_at };
}

async function getToken(profile: string): Promise<string> {
  const cached = secret.get<Cached>(`token:${profile}`);
  if (isFresh(cached)) return cached!.token;
  const config = secret.get<Config>(`config:${profile}`);
  if (!config) throw new Error(`profile "${profile}" not configured; run: ${SETUP_USAGE}`);
  const fresh = await fetchToken(config);
  secret.set(`token:${profile}`, fresh);
  return fresh.token;
}

async function setup(profile: string, args: string[]) {
  const { values } = parseArgs({
    args,
    options: {
      "app-id": { type: "string" },
      "installation-id": { type: "string" },
      "private-key-path": { type: "string" },
    },
  });
  const {
    "app-id": appId,
    "installation-id": installationId,
    "private-key-path": keyPath,
  } = values;
  if (!appId || !installationId || !keyPath) throw new Error(`usage: ${SETUP_USAGE}`);
  const config = { appId, installationId, privateKey: readFileSync(keyPath, "utf8") };
  const token = await fetchToken(config); // verify before saving
  secret.set(`config:${profile}`, config);
  secret.set(`token:${profile}`, token);
  console.error(
    `gain: saved profile "${profile}" to Keychain (service "${SERVICE}"). You can now delete ${keyPath}.`,
  );
}

if (import.meta.main) {
  let args = process.argv.slice(2);
  let profile = process.env.GH_APP_PROFILE || "default";
  if (args[0] === "--profile") [profile, args] = [args[1], args.slice(2)];
  let token: string;
  try {
    // The name ends up in a `security -i` command line, so keep it to safe characters.
    if (!/^[\w.-]+$/.test(profile ?? "")) {
      throw new Error("--profile needs a name of [A-Za-z0-9_.-]");
    }
    if (args[0] === "setup") process.exit((await setup(profile, args.slice(1)), 0));
    if (args[0] === "token") process.exit((console.log(await getToken(profile)), 0));
    if (args[0] === "credential") {
      // store/erase are no-ops; the token lives in Keychain already.
      if (args[1] === "get" && isGitHubHttps(readFileSync(0, "utf8"))) {
        console.log(`username=x-access-token\npassword=${await getToken(profile)}`);
      }
      process.exit(0);
    }
    token = await getToken(profile);
  } catch (e) {
    console.error(`gain: ${(e as Error).message}`);
    process.exit(1);
  }
  const { status, signal, error } = spawnSync("gh", args, {
    stdio: "inherit",
    env: { ...process.env, GH_TOKEN: token },
  });
  if (error) {
    console.error(`gain: failed to run gh: ${error.message}`);
    process.exit(127);
  }
  // Killed by a signal: status is null; exit 128+signo like a shell.
  process.exit(status ?? 128 + (signal ? constants.signals[signal] : 0));
}
