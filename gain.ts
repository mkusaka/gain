#!/usr/bin/env node
// Run `gh` with a GitHub App installation token in GH_TOKEN. Runs on Node (>=24.2) or Bun, macOS only.
// Usage: gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE   (stores in macOS Keychain)
//        gain [--profile NAME] <gh args...>   e.g. gain --profile work pr list -R org/repo
//        gain [--profile NAME] token          print the token (for curl, scripts, ...)
//        gain [--profile NAME] credential get git credential helper (see README)
//        gain profile list | gain profile remove NAME
// Profile defaults to $GH_APP_PROFILE, then "default".
import { spawnSync } from "node:child_process";
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { constants } from "node:os";
import { parseArgs } from "node:util";

type Config = { clientId: string; installationId: string; privateKey: string };
type Cached = { token: string; expires_at: string };

const SERVICE = "gain";
const SETUP_USAGE =
  "gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE";

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
  /** Returns false if the item didn't exist. */
  delete(name: string): boolean {
    const r = spawnSync("security", ["delete-generic-password", "-s", SERVICE, "-a", name], {
      encoding: "utf8",
    });
    if (r.status === 44) return false;
    if (r.status !== 0) throw new Error(`keychain delete failed: ${r.stderr || r.error}`);
    return true;
  },
};

// Profile names from `security dump-keychain` output (attributes only; no secret data without -d).
export function listProfiles(dump: string): string[] {
  return dump
    .split(/^keychain: /m)
    .filter((item) => item.includes(`"svce"<blob>="${SERVICE}"`))
    .flatMap((item) => item.match(/"acct"<blob>="config:([\w.-]+)"/)?.[1] ?? [])
    .sort();
}

// Names end up in a `security -i` command line, so keep them to safe characters.
function checkProfileName(name: string | undefined): string {
  if (!/^[\w.-]+$/.test(name ?? "")) throw new Error("profile names must match [A-Za-z0-9_.-]+");
  return name!;
}

const b64url = (s: string | Buffer) => Buffer.from(s).toString("base64url");

export function createJwt(
  clientId: string,
  privateKey: string,
  now = Math.floor(Date.now() / 1000),
): string {
  // GitHub rejects exp more than 10 minutes out; iat is backdated for clock skew.
  const body = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64url(
    JSON.stringify({ iat: now - 60, exp: now + 540, iss: clientId }),
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

// Authenticated as the App itself (JWT), not an installation.
const appFetch = (path: string, clientId: string, privateKey: string, method = "GET") =>
  fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${createJwt(clientId, privateKey)}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "gain",
    },
  });

type Installation = { id: number; account: { login: string } };

export function pickInstallation(installations: Installation[]): string {
  if (installations.length === 1) return String(installations[0].id);
  if (!installations.length) throw new Error("the App is not installed anywhere; install it first");
  const list = installations.map((i) => `${i.id} (${i.account.login})`).join(", ");
  throw new Error(`the App has several installations; pass --installation-id: ${list}`);
}

async function findInstallationId(clientId: string, privateKey: string): Promise<string> {
  const res = await appFetch("/app/installations?per_page=100", clientId, privateKey);
  if (!res.ok) throw new Error(`installation lookup failed: ${res.status} ${await res.text()}`);
  return pickInstallation((await res.json()) as Installation[]);
}

async function fetchToken({ clientId, installationId, privateKey }: Config): Promise<Cached> {
  const res = await appFetch(
    `/app/installations/${installationId}/access_tokens`,
    clientId,
    privateKey,
    "POST",
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
      "client-id": { type: "string" },
      "installation-id": { type: "string" },
      "private-key-path": { type: "string" },
    },
  });
  const {
    "client-id": clientId,
    "installation-id": installationId,
    "private-key-path": keyPath,
  } = values;
  if (!clientId || !keyPath) throw new Error(`usage: ${SETUP_USAGE}`);
  const privateKey = readFileSync(keyPath, "utf8");
  const config = {
    clientId,
    installationId: installationId ?? (await findInstallationId(clientId, privateKey)),
    privateKey,
  };
  const token = await fetchToken(config); // verify before saving
  secret.set(`config:${profile}`, config);
  secret.set(`token:${profile}`, token);
  console.error(
    `gain: saved profile "${profile}" (installation ${config.installationId}) to Keychain (service "${SERVICE}"). You can now delete ${keyPath}.`,
  );
}

if (import.meta.main) {
  let args = process.argv.slice(2);
  let profile = process.env.GH_APP_PROFILE || "default";
  if (args[0] === "--profile") [profile, args] = [args[1], args.slice(2)];
  let token: string;
  try {
    if (args[0] === "profile" && args[1] === "list") {
      // Attributes of every item in the keychain: can exceed spawnSync's 1 MiB default buffer.
      const dump = spawnSync("security", ["dump-keychain"], {
        encoding: "utf8",
        maxBuffer: 256 * 1024 * 1024,
      });
      if (dump.status !== 0) throw new Error(`keychain list failed: ${dump.stderr || dump.error}`);
      process.exit((listProfiles(dump.stdout).forEach((p) => console.log(p)), 0));
    }
    if (args[0] === "profile" && args[1] === "remove") {
      const name = checkProfileName(args[2]);
      if (!secret.delete(`config:${name}`)) throw new Error(`profile "${name}" not found`);
      secret.delete(`token:${name}`);
      process.exit((console.error(`gain: removed profile "${name}"`), 0));
    }
    if (args[0] === "profile")
      throw new Error("usage: gain profile list | gain profile remove NAME");
    checkProfileName(profile);
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
