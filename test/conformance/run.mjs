// OpenID Foundation RP conformance driver for the Warden reference RP.
//
// For every module of the selected plans it starts a fresh reference RP
// (consumer/, public Warden API only) against the suite's alias issuer, drives
// the front channel headlessly with a cookie jar, waits for the suite's own
// verdict and archives the module log. Results go to build/conformance/.
// Run through `scripts/conformance` (needs `scripts/conformance-suite up`).
// TLS is verified everywhere: Node trusts the disposable test CA through
// NODE_EXTRA_CA_CERTS and the suite presents a certificate from that CA.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "../..");
const SUITE = "https://localhost.emobix.co.uk:8443";
const ALIAS = "warden";
const ISSUER = `${SUITE}/test/a/${ALIAS}/`;
const APP_PORT = 18090;
const APP = `https://localhost:${APP_PORT}`;
const OUT = path.join(ROOT, "build/conformance");
const PKI = path.join(ROOT, "build/test-pki");
const SECRET = crypto.randomBytes(24).toString("base64url");
fs.mkdirSync(OUT, { recursive: true });

const common = {
  client_registration: "static_client",
  request_type: "plain_http_request",
};
const PLANS = {
  basic: {
    name: "oidcc-client-basic-certification-test-plan",
    variant: common,
    mode: "query",
  },
  formpost: {
    name: "oidcc-client-formpost-basic-certification-test-plan",
    variant: common,
    mode: "form_post",
  },
  config: {
    name: "oidcc-client-config-certification-test-plan",
    variant: {
      ...common,
      client_auth_type: "client_secret_basic",
      response_mode: "default",
    },
    mode: "query",
  },
  thirdparty: {
    name: "oidcc-client-test-3rd-party-init-login-test-plan",
    variant: {
      ...common,
      client_auth_type: "client_secret_basic",
      response_mode: "default",
      response_type: "code",
    },
    mode: "query",
    thirdParty: true,
  },
  refresh: {
    name: "oidcc-client-refreshtoken-test-plan",
    variant: {
      ...common,
      client_auth_type: "client_secret_basic",
      response_mode: "default",
      response_type: "code",
    },
    mode: "query",
    refresh: true,
  },
  logout: {
    name: "oidcc-client-rp-initiated-logout-rp-basic",
    variant: {
      ...common,
      client_auth_type: "client_secret_basic",
      response_mode: "default",
    },
    mode: "query",
    logout: true,
  },
};
const selected = (
  process.argv[2] ?? "basic,formpost,config,thirdparty,refresh,logout"
).split(",");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, url, body) {
  const r = await fetch(`${SUITE}${url}`, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  if (!r.ok)
    throw new Error(`${method} ${url}: ${r.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

async function waitStatus(id, wanted, timeoutMs) {
  const end = Date.now() + timeoutMs;
  let info;
  while (Date.now() < end) {
    info = await api("GET", `/api/info/${id}`);
    if (wanted.includes(info.status)) return info;
    await sleep(500);
  }
  return info;
}

function startApp(mode) {
  const env = {
    ...process.env,
    WARDEN_ISSUER: ISSUER,
    WARDEN_CLIENT_ID: "warden-conformance",
    WARDEN_CLIENT_SECRET: SECRET,
    WARDEN_BASE_URL: APP,
    WARDEN_RESPONSE_MODE: mode,
    WARDEN_SCOPES: "profile email",
    WARDEN_CA_FILE: path.join(PKI, "ca.pem"),
    WARDEN_ALLOW_LOOPBACK: "1",
    WARDEN_TLS_CERT: path.join(PKI, "localhost.pem"),
    WARDEN_TLS_KEY: path.join(PKI, "localhost.key"),
    PORT: String(APP_PORT),
    WARDEN_ASSUME_UNADVERTISED_S256: process.env.ASSUME_S256 ?? "1",
  };
  const ebin = fs
    .readdirSync(path.join(ROOT, "consumer/build/dev/erlang"))
    .map((d) => `consumer/build/dev/erlang/${d}/ebin`);
  const child = spawn(
    "erl",
    [
      "-noshell",
      ...ebin.flatMap((e) => ["-pa", e]),
      "-eval",
      "warden_reference:main()",
    ],
    { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.on("data", (d) => (output += d));
  child.stderr.on("data", (d) => (output += d));
  return { child, output: () => output };
}

async function appReady(app) {
  for (let i = 0; i < 60; i++) {
    if (app.child.exitCode !== null) return false;
    try {
      const r = await fetch(`${APP}/health`);
      if (r.ok) return true;
    } catch {}
    await sleep(250);
  }
  return false;
}

// Minimal browser: cookie jar, manual redirects, form_post auto-submission.
class Browser {
  constructor() {
    this.jar = new Map();
  }
  cookieHeader() {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  store(r) {
    for (const c of r.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      this.jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
  }
  async request(url, init = {}) {
    const headers = { ...(init.headers ?? {}) };
    if (url.startsWith(APP)) headers.cookie = this.cookieHeader();
    const r = await fetch(url, { ...init, headers, redirect: "manual" });
    if (url.startsWith(APP)) this.store(r);
    return r;
  }
  // Follow redirects and form_post pages until a page that is neither.
  async navigate(url, limit = 10) {
    let r = await this.request(url);
    for (let i = 0; i < limit; i++) {
      if (r.status >= 300 && r.status < 400) {
        url = new URL(r.headers.get("location"), url).href;
        r = await this.request(url);
        continue;
      }
      const body = await r.text();
      const tag = body.match(/<form\b[^>]*>/i)?.[0] ?? "";
      const action = tag.match(/action=["']([^"']+)["']/i)?.[1];
      const form =
        /method=["']?post/i.test(tag) && action ? [tag, action] : null;
      if (r.status === 200 && form && form[1].startsWith(APP)) {
        const inputs = [
          ...body.matchAll(
            /<input[^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']/gi,
          ),
        ].map((m) => [
          m[1],
          m[2].replace(/&quot;/g, '"').replace(/&amp;/g, "&"),
        ]);
        url = form[1];
        r = await this.request(url, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(inputs).toString(),
        });
        continue;
      }
      if (process.env.DUMP)
        fs.writeFileSync(
          path.join(OUT, "last-page.html"),
          `${url}\n${r.status}\n${body}`,
        );
      return { url, status: r.status, body };
    }
    return { url, status: r.status, body: "" };
  }
}

let chrome = null;
async function chromeVisit(url) {
  if (!chrome) {
    const { chromium } = await import(
      path.join(ROOT, "consumer/browser/node_modules/playwright-core/index.mjs")
    );
    const spki = ["localhost.pem", "conformance.pem"].map((f) =>
      crypto
        .createHash("sha256")
        .update(
          new crypto.X509Certificate(
            fs.readFileSync(path.join(PKI, f)),
          ).publicKey.export({ type: "spki", format: "der" }),
        )
        .digest("base64"),
    );
    chrome = await chromium.launch({
      channel: "chrome",
      headless: true,
      args: [`--ignore-certificate-errors-spki-list=${spki.join(",")}`],
    });
  }
  const page = await chrome.newPage();
  try {
    await page.goto(url);
    await page.waitForURL((u) => u.href.startsWith(`${APP}/logged-out`), {
      timeout: 15000,
    });
    return `redirected to ${new URL(page.url()).pathname}?state=${new URL(page.url()).searchParams.get("state") ? "present" : "absent"}`;
  } catch (e) {
    return `no redirect (${String(e.message).split("\n")[0].slice(0, 80)})`;
  } finally {
    await page.close();
  }
}

async function runModule(plan, planId, module) {
  const { id } = await api(
    "POST",
    `/api/runner?test=${encodeURIComponent(module)}&plan=${planId}`,
  );
  await waitStatus(id, ["WAITING", "FINISHED", "INTERRUPTED"], 30000);
  // Third-party initiation: the suite queues the initiation URL and rejects
  // provider requests until the browser visit is registered.
  let initiation = [];
  if (plan.thirdParty) {
    for (let i = 0; i < 20 && initiation.length === 0; i++) {
      initiation = await api("GET", `/api/runner/browser/${id}`).then(
        (b) => b.urls ?? [],
      );
      if (!initiation.length) await sleep(500);
    }
    for (const u of initiation)
      await api(
        "POST",
        `/api/runner/browser/${id}/visit?url=${encodeURIComponent(u)}`,
      );
  }
  const app = startApp(plan.mode);
  const notes = [];
  try {
    const ready = await appReady(app);
    if (!ready) {
      const reason =
        app.output().match(/warden did not start: ([^"<]+)/)?.[1] ??
        app.output().slice(0, 300);
      notes.push("reference RP refused to start: " + reason);
    } else if ((await api("GET", `/api/info/${id}`)).status === "FINISHED") {
      // Discovery/JWKS-only modules finish during RP startup; a login would
      // be an illegal request for a finished test.
      notes.push("module finished during RP startup");
    } else {
      const browser = new Browser();
      if (plan.thirdParty) {
        for (const u of initiation) {
          const page = await browser.navigate(u);
          notes.push(
            `third-party initiation → ${page.status} ${new URL(page.url).pathname}`,
          );
        }
      } else {
        const page = await browser.navigate(`${APP}/login`);
        notes.push(`login → ${page.status} ${new URL(page.url).pathname}`);
        if (module.endsWith("signing-key-rotation")) {
          // This module rotates keys between two complete logins.
          const second = await new Browser().navigate(`${APP}/login`);
          notes.push(
            `second login → ${second.status} ${new URL(second.url).pathname}`,
          );
        }
        if (page.status === 200 && new URL(page.url).pathname === "/") {
          if (plan.refresh) {
            // A browser form post carries its page's origin.
            const r = await browser.request(`${APP}/refresh`, {
              method: "POST",
              headers: { origin: APP },
            });
            const text = await r.text();
            notes.push(
              `refresh → ${text.match(/id="refresh-outcome">([^<]+)/)?.[1]}`,
            );
          }
          if (plan.logout) {
            // A browser form post carries its page's origin.
            const r = await browser.request(`${APP}/logout`, {
              method: "POST",
              headers: { origin: APP },
            });
            const location = r.headers.get("location");
            notes.push(
              `logout → ${r.status} ${location ? new URL(location).origin + new URL(location).pathname : ""}`,
            );
            if (location) {
              // The suite's end-session page runs front-channel logout in
              // JavaScript, so this step uses the installed Chrome.
              notes.push(`end session → ${await chromeVisit(location)}`);
            }
          }
        }
      }
    }
    const info = await waitStatus(id, ["FINISHED", "INTERRUPTED"], 60000);
    const log = await api("GET", `/api/log/${id}`);
    fs.writeFileSync(
      path.join(OUT, `${module}-${plan.mode}.log.json`),
      JSON.stringify(log, null, 2),
    );
    return {
      module,
      id,
      status: info.status,
      result: info.result ?? "NONE",
      notes,
    };
  } finally {
    // Wait until the RP has exited so the next module can bind the port.
    const exited = new Promise((resolve) => app.child.once("exit", resolve));
    app.child.kill();
    await Promise.race([exited, sleep(5000)]);
    for (let i = 0; i < 20; i++) {
      try {
        await fetch(`${APP}/health`);
        await sleep(250);
      } catch {
        break;
      }
    }
  }
}

const summary = [];
for (const key of selected) {
  const plan = PLANS[key];
  const config = {
    alias: ALIAS,
    description: `Warden reference RP (${key})`,
    waitTimeoutSeconds: 5,
    client: {
      client_id: "warden-conformance",
      client_secret: SECRET,
      redirect_uri: `${APP}/callback`,
      post_logout_redirect_uri: `${APP}/logged-out`,
      frontchannel_logout_uri: `${APP}/frontchannel-logout`,
      initiate_login_uri: `${APP}/initiate-login`,
      scope: "openid profile email",
    },
  };
  const created = await api(
    "POST",
    `/api/plan?planName=${plan.name}&variant=${encodeURIComponent(JSON.stringify(plan.variant))}`,
    config,
  );
  const planId = created.id;
  const only = process.env.MODULES ? process.env.MODULES.split(",") : null;
  const modules = created.modules
    .map((m) => m.testModule)
    .filter((m) => !only || only.includes(m));
  for (const module of modules) {
    const row = await runModule(plan, planId, module).catch((e) => ({
      module,
      status: "DRIVER_ERROR",
      result: "NONE",
      notes: [String(e.message ?? e)],
    }));
    row.plan = plan.name;
    summary.push(row);
    console.log(
      `${row.result.padEnd(8)} ${row.status.padEnd(11)} ${plan.name} ${module}  ${row.notes.join(" | ")}`,
    );
  }
  try {
    const r = await fetch(`${SUITE}/api/plan/exporthtml/${planId}`);
    fs.writeFileSync(
      path.join(OUT, `${key}-export.zip`),
      Buffer.from(await r.arrayBuffer()),
    );
  } catch {}
}
if (chrome) await chrome.close();
fs.writeFileSync(
  path.join(OUT, `summary-${selected.join("_")}.json`),
  JSON.stringify(
    {
      suite: "release-v5.3.1",
      issuer: ISSUER,
      policy:
        (process.env.ASSUME_S256 ?? "1") === "1"
          ? "NON-DEFAULT: AssumeS256WhenUnadvertised (public opt-in, decision D7)"
          : "default",
      summary,
    },
    null,
    2,
  ),
);
