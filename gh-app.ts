#!/usr/bin/env bun
// Run `gh` with a GitHub App installation token in GH_TOKEN.
// Usage: gh-app [--profile NAME] setup --app-id ID --installation-id ID --private-key-path FILE   (stores in macOS Keychain)
//        gh-app [--profile NAME] <gh args...>   e.g. gh-app --profile work pr list -R org/repo
// Profile defaults to $GH_APP_PROFILE, then "default".
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { constants } from "node:os";
import { parseArgs } from "node:util";

type Config = { appId: string; installationId: string; privateKey: string };
type Cached = { token: string; expires_at: string };

const SERVICE = "gh-app";
const SETUP_USAGE =
  "gh-app [--profile NAME] setup --app-id ID --installation-id ID --private-key-path FILE";
const secret = {
  get: async <T>(name: string): Promise<T | undefined> => {
    const v = await Bun.secrets.get({ service: SERVICE, name });
    return v ? JSON.parse(v) : undefined;
  },
  set: (name: string, v: unknown) =>
    Bun.secrets.set({ service: SERVICE, name, value: JSON.stringify(v) }),
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

export const isFresh = (c: Cached | undefined, now = Date.now()) =>
  !!c && Date.parse(c.expires_at) - now > 60_000;

async function fetchToken({ appId, installationId, privateKey }: Config): Promise<Cached> {
  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${createJwt(appId, privateKey)}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gh-app",
      },
    },
  );
  if (!res.ok) throw new Error(`token request failed: ${res.status} ${await res.text()}`);
  const { token, expires_at } = (await res.json()) as Cached;
  return { token, expires_at };
}

async function getToken(profile: string): Promise<string> {
  const cached = await secret.get<Cached>(`token:${profile}`);
  if (isFresh(cached)) return cached!.token;
  const config = await secret.get<Config>(`config:${profile}`);
  if (!config) throw new Error(`profile "${profile}" not configured; run: ${SETUP_USAGE}`);
  const fresh = await fetchToken(config);
  await secret.set(`token:${profile}`, fresh);
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
  await secret.set(`config:${profile}`, config);
  await secret.set(`token:${profile}`, token);
  console.error(
    `gh-app: saved profile "${profile}" to Keychain (service "${SERVICE}"). You can now delete ${keyPath}.`,
  );
}

if (import.meta.main) {
  let args = process.argv.slice(2);
  let profile = process.env.GH_APP_PROFILE || "default";
  if (args[0] === "--profile") [profile, args] = [args[1], args.slice(2)];
  let token: string;
  try {
    if (!profile) throw new Error("--profile requires a name");
    if (args[0] === "setup") process.exit((await setup(profile, args.slice(1)), 0));
    token = await getToken(profile);
  } catch (e) {
    console.error(`gh-app: ${(e as Error).message}`);
    process.exit(1);
  }
  const { exitCode, signalCode } = Bun.spawnSync(["gh", ...args], {
    stdio: ["inherit", "inherit", "inherit"],
    env: { ...process.env, GH_TOKEN: token },
  });
  // Killed by a signal: exitCode is null; exit 128+signo like a shell.
  process.exit(exitCode ?? 128 + (constants.signals[signalCode!] ?? 0));
}
