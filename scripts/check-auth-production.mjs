import { spawn } from "node:child_process";
import assert from "node:assert/strict";
import { osEnvironment } from "../runtime/secrets.mjs";
import { request as httpRequest } from "node:http";
import { resolve } from "node:path";
import { gunzipSync } from "node:zlib";

const canonical = new URL("https://app.example");

function request(port, path, headers = {}) {
  // Node fetch normalizes Host to its URL. Simulate TLS termination explicitly
  // with node:http so the canonical external Host reaches the loopback server.
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        path,
        headers: {
          host: canonical.host,
          "x-forwarded-host": canonical.host,
          "x-forwarded-proto": "https",
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("error", reject);
        res.on("end", () => {
          try {
            const bytes = Buffer.concat(chunks);
            if (res.headers["content-length"] !== undefined)
              assert.equal(Number(res.headers["content-length"]), bytes.length);
            const encoding = res.headers["content-encoding"];
            assert.ok(!encoding || encoding === "gzip", "Unexpected HTTP encoding");
            const responseHeaders = new Headers();
            for (const [key, value] of Object.entries(res.headers))
              for (const v of Array.isArray(value) ? value : [value])
                if (v !== undefined) responseHeaders.append(key, v);
            resolve(
              new Response(encoding === "gzip" ? gunzipSync(bytes) : bytes, {
                status: res.statusCode,
                headers: responseHeaders,
              }),
            );
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    req.on("error", reject);
    req.setTimeout(5000, () => req.destroy(new Error("Smoke timeout")));
    req.end();
  });
}
export async function verifyProductionHttp(port, { assets = false } = {}) {
  const compressed = { "accept-encoding": "gzip" };
  const login = await request(port, "/login", compressed);
  assert.equal(login.status, 200, "Login page status");
  assert.equal(login.headers.get("content-encoding"), "gzip", "Login page compression");
  assert.match(login.headers.get("content-type") ?? "", /^text\/html/);
  const html = await login.text();
  assert.match(html, /<html[\s>]/i);

  for (const path of [
    "/",
    "/friends/bean",
    "/account",
    "/onboarding",
    "/admin/access",
    "/my-timetable/import",
  ]) {
    const r = await request(port, path, compressed);
    assert.equal(r.status, 307);
    assert.equal(r.headers.get("location"), canonical.origin + "/login");
  }
  const providerResponse = await request(port, "/api/auth/providers", compressed);
  assert.equal(providerResponse.status, 200, "Auth.js providers status");
  const providers = await providerResponse.json();
  assert.equal(
    providers.keycloak.callbackUrl,
    canonical.origin + "/api/auth/callback/keycloak",
  );
  const csrf = await request(port, "/api/auth/csrf", compressed);
  assert.equal(csrf.status, 200, "Auth.js CSRF status");
  assert.ok(typeof (await csrf.json()).csrfToken === "string");
  assert.equal(csrf.headers.get("referrer-policy"), "no-referrer");
  const cookies = csrf.headers.getSetCookie();
  assert.ok(cookies.length);
  for (const cookie of cookies) {
    assert.match(cookie, /; Secure/i);
    assert.match(cookie, /; HttpOnly/i);
    assert.match(cookie, /; SameSite=Lax/i);
  }
  const rejected = await request(port, "/api/auth/providers", {
    "x-forwarded-host": "untrusted.example",
  });
  assert.equal(rejected.status, 400);
  assert.equal(await (await request(port, "/api/auth/session")).json(), null);

  if (assets) {
    const bundle = html.match(/src="(\/_next\/static\/[^"]+\.js)"/)?.[1];
    assert.ok(bundle, "Login references a packaged Next.js script");
    const script = await request(port, bundle);
    assert.equal(script.status, 200, "Packaged Next.js script status");
    assert.match(script.headers.get("content-type") ?? "", /javascript/);
    const brand = await request(port, "/brand/koonpinai-mark.svg");
    assert.equal(brand.status, 200, "Packaged brand asset status");
    assert.match(brand.headers.get("content-type") ?? "", /^image\/svg\+xml/);
    const image = await request(port, "/_next/image?url=%2Ficons%2Ficon-192x192.png&w=256&q=75", {
      accept: "image/webp",
    });
    assert.equal(image.status, 200, "Packaged image optimizer status");
    assert.match(image.headers.get("content-type") ?? "", /^image\/webp/);
    assert.ok((await image.arrayBuffer()).byteLength > 0);
  }
}

async function main() {
  const artifact = process.argv[2];
  const server = resolve(artifact ?? ".next/standalone", "server.js");
  const port = 3200;
  const child = spawn(process.execPath, [server], {
    stdio: "ignore",
    env: {
      ...osEnvironment(),
      NODE_ENV: "production",
      PORT: String(port),
      HOSTNAME: "127.0.0.1",
      ENABLE_UI_PREVIEW: "true",
      ENABLE_ADMIN_DEMO: "true",
      AUTH_URL: canonical.origin,
      AUTH_SECRET: "production-smoke-fixture-secret-at-least-32-characters",
      AUTH_KEYCLOAK_ID: "fixture-client",
      AUTH_KEYCLOAK_SECRET: "fixture-secret",
      AUTH_KEYCLOAK_ISSUER: "https://sso.kmitl.ac.th/realms/kmitl",
      DATABASE_URL: "postgres://fixture:fixture@127.0.0.1:1/fixture",
    },
  });
  try {
    let ready = false;
    for (let n = 0; n < 40 && child.exitCode === null; n++) {
      try {
        if ((await request(port, "/login")).status === 200) {
          ready = true;
          break;
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    assert.ok(ready, "Start the built app on the reserved smoke-test port");
    await verifyProductionHttp(port, { assets: Boolean(artifact) });
    console.log("Production HTTP smoke passed with fixture credentials and no live SSO.");
  } catch (error) {
    console.error("Production HTTP smoke failed at check line %s; response details are redacted.",
      error instanceof Error ? error.stack?.match(/check-auth-production\.mjs:(\d+)/)?.[1] ?? "unknown" : "unknown");
    process.exitCode = 1;
  } finally {
    child.kill();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
  void main();
}
