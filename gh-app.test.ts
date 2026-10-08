import { expect, test } from "bun:test";
import { generateKeyPairSync, verify } from "node:crypto";
import { createJwt, isFresh } from "./gh-app.ts";

test("createJwt signs a PKCS#1 key with valid claims", () => {
  // GitHub hands out PKCS#1 PEMs.
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const [h, p, sig] = createJwt("123", privateKey, 1000).split(".");
  expect(
    verify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig, "base64url")),
  ).toBe(true);
  expect(JSON.parse(Buffer.from(p, "base64url").toString())).toEqual({
    iat: 940,
    exp: 1540,
    iss: "123",
  });
});

test("isFresh requires more than a minute of validity", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  expect(isFresh({ token: "t", expires_at: "2026-01-01T00:05:00Z" }, now)).toBe(true);
  expect(isFresh({ token: "t", expires_at: "2026-01-01T00:00:30Z" }, now)).toBe(false);
  expect(isFresh(undefined, now)).toBe(false);
});
