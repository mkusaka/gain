#!/usr/bin/env node
// Run `gh` with a GitHub App installation token in GH_TOKEN. Runs on Node (>=24.2) or Bun, macOS only.
// Private keys live only inside `gain agent`, encrypted at rest with a passphrase; clients get tokens.
// Usage: gain agent start | unlock | lock | stop | status | install | uninstall (launchd)
//        gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE
//        gain [--profile NAME] <gh args...>   e.g. gain --profile work pr list -R org/repo
//        gain [--profile NAME] token [--min-ttl MINUTES]   print the token (for curl, scripts, ...)
//        gain [--profile NAME] revoke         revoke the cached token (e.g. after it leaked)
//        gain [--profile NAME] credential get git credential helper (see README)
//        gain profile list | gain profile remove NAME
//        gain migrate-keychain                move profiles from gain <= 0.3's Keychain items
// Profile defaults to $GH_APP_PROFILE, then "default".
import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createSign, randomBytes, scryptSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { connect, createServer } from "node:net";
import { constants, homedir } from "node:os";
import { join } from "node:path";
import { object, or } from "@optique/core/constructs";
import { optional, withDefault } from "@optique/core/modifiers";
import { argument, command, constant, option, passThrough } from "@optique/core/primitives";
import { choice, integer, string } from "@optique/core/valueparser";
import { run } from "@optique/run";

type Config = { clientId: string; installationId: string; privateKey: string };
type Cached = { token: string; expires_at: string };

const DIR = join(homedir(), ".local/share/gain");
const VAULT = join(DIR, "vault");
const SOCKET = join(DIR, "agent.sock");
const LABEL = "com.github.mkusaka.gain.agent";
const PLIST = join(homedir(), `Library/LaunchAgents/${LABEL}.plist`);
const SETUP_USAGE =
  "gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE";

// Vault: AES-256-GCM over the profiles JSON, key from the passphrase via scrypt (~0.3s, 128 MiB).
const KDF = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
export const deriveKey = (passphrase: string, salt: Buffer) =>
  scryptSync(passphrase, salt, 32, KDF);

export function seal(key: Buffer, salt: Buffer, profiles: Map<string, Config>): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const plain = JSON.stringify(Object.fromEntries(profiles));
  const data = Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()]);
  return JSON.stringify({ salt: salt.toString("base64"), data: data.toString("base64") });
}

export function unseal(key: Buffer, data: Buffer): Map<string, Config> {
  const d = createDecipheriv("aes-256-gcm", key, data.subarray(0, 12));
  d.setAuthTag(data.subarray(-16));
  let plain: Buffer;
  try {
    plain = Buffer.concat([d.update(data.subarray(12, -16)), d.final()]);
  } catch {
    throw new Error("wrong passphrase");
  }
  return new Map(Object.entries(JSON.parse(plain.toString())));
}

// Profile names: keep them to safe characters (also used in the old Keychain item names).
function checkProfileName(name: unknown): string {
  if (typeof name !== "string" || !/^[\w.-]+$/.test(name))
    throw new Error("profile names must match [A-Za-z0-9_.-]+");
  return name;
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

// Minutes of headroom so long-running commands (e.g. `gh run watch`) don't outlive the token.
export const isFresh = (c: Cached | undefined, minTtl = 5, now = Date.now()) =>
  !!c && Date.parse(c.expires_at) - now > minTtl * 60_000;

// git credential protocol: key=value lines on stdin. Only answer for https://github.com.
export function isGitHubHttps(request: string): boolean {
  const fields = Object.fromEntries(
    request.split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );
  return fields.protocol === "https" && fields.host === "github.com";
}

const githubFetch = (path: string, bearer: string, method = "GET") =>
  fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${bearer}`,
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
  const res = await githubFetch("/app/installations?per_page=100", createJwt(clientId, privateKey));
  if (!res.ok) throw new Error(`installation lookup failed: ${res.status} ${await res.text()}`);
  return pickInstallation((await res.json()) as Installation[]);
}

async function fetchToken({ clientId, installationId, privateKey }: Config): Promise<Cached> {
  const res = await githubFetch(
    `/app/installations/${installationId}/access_tokens`,
    createJwt(clientId, privateKey),
    "POST",
  );
  if (!res.ok) throw new Error(`token request failed: ${res.status} ${await res.text()}`);
  const { token, expires_at } = (await res.json()) as Cached;
  return { token, expires_at };
}

// Holds the decrypted profiles while unlocked. No request returns a private key.
// Tokens are cached in memory only, so a restart or lock just mints new ones.
export class Agent {
  key?: Buffer;
  salt?: Buffer;
  profiles = new Map<string, Config>();
  tokens = new Map<string, Cached>();
  vaultPath: string;
  constructor(vaultPath: string) {
    this.vaultPath = vaultPath;
  }

  unlock(passphrase: string) {
    if (this.key) return;
    if (existsSync(this.vaultPath)) {
      const { salt, data } = JSON.parse(readFileSync(this.vaultPath, "utf8"));
      const s = Buffer.from(salt, "base64");
      const key = deriveKey(passphrase, s);
      this.profiles = unseal(key, Buffer.from(data, "base64"));
      [this.key, this.salt] = [key, s];
    } else {
      this.salt = randomBytes(16);
      this.key = deriveKey(passphrase, this.salt);
      this.save();
    }
  }

  lock() {
    this.key?.fill(0);
    this.key = undefined;
    this.profiles.clear();
    this.tokens.clear();
  }

  save() {
    const tmp = `${this.vaultPath}.tmp`;
    writeFileSync(tmp, seal(this.key!, this.salt!, this.profiles), { mode: 0o600 });
    renameSync(tmp, this.vaultPath);
  }

  async token(profile: string, minTtl?: number): Promise<string> {
    const cached = this.tokens.get(profile);
    if (isFresh(cached, minTtl)) return cached!.token;
    const config = this.profiles.get(profile);
    if (!config) throw new Error(`profile "${profile}" not configured; run: ${SETUP_USAGE}`);
    const fresh = await fetchToken(config);
    this.tokens.set(profile, fresh);
    return fresh.token;
  }

  // Tokens already handed out earlier stay valid until they expire; this only revokes the cached one.
  async revoke(profile: string): Promise<string> {
    const cached = this.tokens.get(profile);
    if (!cached) return "no cached token";
    if (isFresh(cached, 0)) {
      const res = await githubFetch("/installation/token", cached.token, "DELETE");
      // 401: already revoked or expired.
      if (!res.ok && res.status !== 401)
        throw new Error(`revoke failed: ${res.status} ${await res.text()}`);
    }
    this.tokens.delete(profile);
    return "revoked the cached token";
  }

  async setup(
    profile: string,
    c: { clientId: string; installationId?: string; privateKey: string },
  ) {
    const config = {
      clientId: String(c.clientId),
      installationId: c.installationId
        ? String(c.installationId)
        : await findInstallationId(c.clientId, c.privateKey),
      privateKey: String(c.privateKey),
    };
    const token = await fetchToken(config); // verify before saving
    this.profiles.set(profile, config);
    this.save();
    this.tokens.set(profile, token);
    return config.installationId;
  }

  async handle(req: Record<string, any>): Promise<Record<string, unknown>> {
    if (req.cmd === "status") return { unlocked: !!this.key };
    if (req.cmd === "lock") return (this.lock(), {});
    if (req.cmd === "unlock") return (this.unlock(String(req.passphrase)), {});
    if (!this.key) throw new Error("the agent is locked; run: gain agent unlock");
    if (req.cmd === "list") return { profiles: [...this.profiles.keys()].sort() };
    const profile = checkProfileName(req.profile);
    if (req.cmd === "token") return { token: await this.token(profile, req.minTtl) };
    if (req.cmd === "revoke") return { message: await this.revoke(profile) };
    if (req.cmd === "setup") return { installationId: await this.setup(profile, req.config) };
    if (req.cmd === "remove") {
      if (!this.profiles.delete(profile)) throw new Error(`profile "${profile}" not found`);
      this.tokens.delete(profile);
      return (this.save(), {});
    }
    throw new Error(`unknown command: ${req.cmd}`);
  }
}

// One JSON request line per connection, one JSON response line back.
function call(req: object): Promise<Record<string, any>> {
  return new Promise((resolve, reject) => {
    let out = "";
    const sock = connect(SOCKET).setEncoding("utf8");
    sock
      .on("connect", () => sock.write(`${JSON.stringify(req)}\n`))
      .on("data", (d) => (out += d))
      .on("end", () => {
        const res = JSON.parse(out || '{"error":"the agent closed the connection"}');
        if (res.error) reject(new Error(res.error));
        else resolve(res);
      })
      .on("error", (e: NodeJS.ErrnoException) =>
        reject(
          e.code === "ENOENT" || e.code === "ECONNREFUSED"
            ? new Error("the agent is not running; start it with: gain agent start")
            : e,
        ),
      );
  });
}

async function startAgent() {
  // Node builds carry get-task-allow (or no hardened runtime), so any same-user process can
  // attach a debugger and read the key. Official Bun builds are hardened without it.
  if (!process.versions.bun) {
    const r = spawnSync("bun", process.argv.slice(1), { stdio: "inherit" });
    if (r.error)
      throw new Error("the agent needs Bun (https://bun.sh): node allows debugger attach");
    process.exit(r.status ?? 1);
  }
  const sig = spawnSync("codesign", ["-dv", "--entitlements", "-", process.execPath], {
    encoding: "utf8",
  });
  const info = `${sig.stdout}${sig.stderr}`;
  if (!/flags=0x\w+\([^)]*runtime/.test(info) || info.includes("get-task-allow"))
    throw new Error(`${process.execPath} allows debugger attach; use an official Bun build`);
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  chmodSync(DIR, 0o700);
  if (existsSync(SOCKET)) {
    const running = await call({ cmd: "status" }).then(
      () => true,
      () => false,
    );
    if (running) throw new Error("another agent is already running");
    rmSync(SOCKET);
  }
  process.umask(0o077);
  const agent = new Agent(VAULT);
  const server = createServer((sock) => {
    sock.setTimeout(10_000, () => sock.destroy()).setEncoding("utf8");
    let buf = "";
    const onData = async (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return void (buf.length > 65_536 && sock.destroy());
      sock.off("data", onData).setTimeout(0);
      let res: Record<string, unknown>;
      try {
        const req = JSON.parse(buf.slice(0, nl));
        if (req.cmd === "stop") return void sock.end('{"ok":true}\n', () => process.exit(0));
        res = { ok: true, ...(await agent.handle(req)) };
      } catch (e) {
        res = { error: (e as Error).message };
      }
      sock.end(`${JSON.stringify(res)}\n`);
    };
    sock.on("data", onData);
  });
  process.on("exit", () => rmSync(SOCKET, { force: true }));
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const)
    process.on(sig, () => process.exit(0));
  server.listen(SOCKET, () => console.error(`gain: agent listening on ${SOCKET} (locked)`));
}

// Read from the terminal without echo; `read -s` restores the tty even on Ctrl-C.
function readSecret(prompt: string): string {
  const r = spawnSync(
    "/bin/bash",
    ["-c", 'read -rsp "$1" s </dev/tty && echo >/dev/tty && printf %s "$s"', "gain", prompt],
    { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
  );
  if (r.status !== 0) throw new Error("no passphrase entered");
  return r.stdout;
}

// launchd runs the agent at login (and right away). No KeepAlive: a restarted agent is locked
// anyway, and a broken path (gain/bun moved) would make launchd retry it every 10 seconds.
export function launchdPlist(args: string[], log: string): string {
  const esc = (v: string) => v.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array>${args.map((a) => `<string>${esc(a)}</string>`).join("")}</array>
  <key>RunAtLoad</key><true/>
  <key>StandardErrorPath</key><string>${esc(log)}</string>
</dict></plist>
`;
}

const launchctl = (...args: string[]) => spawnSync("launchctl", args, { encoding: "utf8" });

async function installAgent() {
  launchctl("bootout", `gui/${process.getuid!()}/${LABEL}`); // replace an older install
  const running = await call({ cmd: "status" }).then(
    () => true,
    () => false,
  );
  if (running) throw new Error("an agent is already running; stop it first: gain agent stop");
  // Absolute paths: launchd has no PATH to speak of, and shims (mise, ...) aren't the real binary.
  const bun = process.versions.bun
    ? process.execPath
    : spawnSync("bun", ["-e", "console.log(process.execPath)"], {
        encoding: "utf8",
      }).stdout?.trim();
  if (!bun) throw new Error("the agent needs Bun (https://bun.sh)");
  const log = join(homedir(), "Library/Logs/gain-agent.log");
  mkdirSync(join(homedir(), "Library/LaunchAgents"), { recursive: true });
  writeFileSync(PLIST, launchdPlist([bun, realpathSync(process.argv[1]), "agent", "start"], log));
  const r = launchctl("bootstrap", `gui/${process.getuid!()}`, PLIST);
  if (r.status !== 0) throw new Error(`launchctl bootstrap failed: ${r.stderr}`);
  return `installed ${PLIST}; the agent starts at login (log: ${log}). Now run: gain agent unlock`;
}

function uninstallAgent() {
  launchctl("bootout", `gui/${process.getuid!()}/${LABEL}`);
  rmSync(PLIST, { force: true });
  return `removed ${PLIST} and stopped the agent`;
}

async function unlockAgent() {
  if ((await call({ cmd: "status" })).unlocked) return "already unlocked";
  if (existsSync(VAULT)) {
    await call({ cmd: "unlock", passphrase: readSecret("gain passphrase: ") });
    return "unlocked";
  }
  const passphrase = readSecret("new gain passphrase (min 12 chars): ");
  if (passphrase.length < 12) throw new Error("passphrase too short");
  if (readSecret("again: ") !== passphrase) throw new Error("passphrases don't match");
  await call({ cmd: "unlock", passphrase });
  return `created ${VAULT} and unlocked; if you forget the passphrase, delete it and set up again`;
}

// Keychain items written by gain <= 0.3: service "gain", accounts config:<p> and token:<p>.
export function listProfiles(dump: string): string[] {
  return dump
    .split(/^keychain: /m)
    .filter((item) => item.includes(`"svce"<blob>="gain"`))
    .flatMap((item) => item.match(/"acct"<blob>="config:([\w.-]+)"/)?.[1] ?? [])
    .sort();
}

async function migrateKeychain() {
  const security = (...args: string[]) =>
    spawnSync("security", args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  const dump = security("dump-keychain");
  if (dump.status !== 0) throw new Error(`keychain list failed: ${dump.stderr || dump.error}`);
  const profiles = listProfiles(dump.stdout);
  if (!profiles.length) return console.error("gain: nothing to migrate");
  for (const profile of profiles) {
    const r = security("find-generic-password", "-s", "gain", "-a", `config:${profile}`, "-w");
    if (r.status !== 0) throw new Error(`keychain read failed: ${r.stderr || r.error}`);
    const config = JSON.parse(Buffer.from(r.stdout.trim(), "base64").toString());
    await call({ cmd: "setup", profile, config });
    // The point of migrating: no copy of the key may stay where any process can read it.
    for (const acct of [`config:${profile}`, `token:${profile}`]) {
      const d = security("delete-generic-password", "-s", "gain", "-a", acct);
      if (d.status !== 0 && d.status !== 44)
        throw new Error(
          `migrated "${profile}" but failed to delete Keychain item ${acct}: ${d.stderr}`,
        );
    }
    console.error(`gain: migrated profile "${profile}" and deleted its Keychain items`);
  }
}

const defaultProfile = () => process.env.GH_APP_PROFILE || "default";

// Anything that isn't a gain command goes to gh untouched, so gain has no --help/--version of its own.
export const parser = withDefault(
  or(
    command(
      "agent",
      object({
        action: constant("agent"),
        op: argument(choice(["start", "unlock", "lock", "stop", "status", "install", "uninstall"])),
      }),
    ),
    command("migrate-keychain", object({ action: constant("migrate-keychain") })),
    command(
      "profile",
      or(
        command("list", object({ action: constant("profile list") })),
        command(
          "remove",
          object({
            action: constant("profile remove"),
            name: argument(string({ metavar: "NAME" })),
          }),
        ),
      ),
    ),
    object({
      profile: withDefault(option("--profile", string({ metavar: "NAME" })), defaultProfile),
      cmd: or(
        command(
          "setup",
          object({
            action: constant("setup"),
            clientId: option("--client-id", string({ metavar: "ID" })),
            installationId: optional(option("--installation-id", string({ metavar: "ID" }))),
            keyPath: option("--private-key-path", string({ metavar: "FILE" })),
          }),
        ),
        command(
          "token",
          object({
            action: constant("token"),
            // Installation tokens live 60 minutes, so more headroom than that can never be met.
            minTtl: withDefault(option("--min-ttl", integer({ min: 0, max: 60 })), 5),
          }),
        ),
        command("revoke", object({ action: constant("revoke") })),
        command(
          "credential",
          object({
            action: constant("credential"),
            op: argument(choice(["get", "store", "erase"])),
          }),
        ),
        object({ action: constant("gh"), args: passThrough({ format: "greedy" }) }),
      ),
    }),
  ),
  () => ({
    profile: defaultProfile(),
    cmd: { action: "gh" as const, args: [] as readonly string[] },
  }),
);

if (import.meta.main) {
  const parsed = run(parser, { programName: "gain" });
  const done = (msg?: string) => process.exit((msg && console.error(`gain: ${msg}`), 0));
  try {
    if ("action" in parsed) {
      if (parsed.action === "agent") {
        if (parsed.op === "start") await startAgent();
        else if (parsed.op === "unlock") done(await unlockAgent());
        else if (parsed.op === "install") done(await installAgent());
        else if (parsed.op === "uninstall") done(uninstallAgent());
        else if (parsed.op === "status")
          done((await call({ cmd: "status" })).unlocked ? "unlocked" : "locked");
        else
          done(
            (await call({ cmd: parsed.op }),
            `agent ${parsed.op === "stop" ? "stopped" : "locked"}`),
          );
      } else if (parsed.action === "migrate-keychain") done(await migrateKeychain());
      else if (parsed.action === "profile list") {
        process.exit(
          ((await call({ cmd: "list" })).profiles.forEach((p: string) => console.log(p)), 0),
        );
      } else {
        const profile = checkProfileName(parsed.name);
        done((await call({ cmd: "remove", profile }), `removed profile "${profile}"`));
      }
    } else {
      const { cmd } = parsed;
      const profile = checkProfileName(parsed.profile);
      if (cmd.action === "setup") {
        const privateKey = readFileSync(cmd.keyPath, "utf8");
        const { clientId, installationId } = cmd;
        const res = await call({
          cmd: "setup",
          profile,
          config: { clientId, installationId, privateKey },
        });
        done(
          `saved profile "${profile}" (installation ${res.installationId}) to the agent's vault. You can now delete ${cmd.keyPath}.`,
        );
      }
      if (cmd.action === "token")
        process.exit(
          (console.log((await call({ cmd: "token", profile, minTtl: cmd.minTtl })).token), 0),
        );
      if (cmd.action === "revoke") done((await call({ cmd: "revoke", profile })).message);
      if (cmd.action === "credential") {
        // store/erase are no-ops; the agent owns the token.
        if (cmd.op === "get" && isGitHubHttps(readFileSync(0, "utf8"))) {
          const { token } = await call({ cmd: "token", profile });
          console.log(`username=x-access-token\npassword=${token}`);
        }
        done();
      }
      if (cmd.action === "gh") {
        const { token } = await call({ cmd: "token", profile });
        const { status, signal, error } = spawnSync("gh", cmd.args, {
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
    }
  } catch (e) {
    console.error(`gain: ${(e as Error).message}`);
    process.exit(1);
  }
}
