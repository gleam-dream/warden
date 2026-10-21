// Real-browser journey through the Warden reference RP and the pinned
// Keycloak (`scripts/browser-journey`). Chrome is the installed Google Chrome,
// driven by Playwright Test. Chrome accepts only the disposable test
// certificate's public key (`--ignore-certificate-errors-spki-list`); no other
// certificate check is relaxed. Results are written to
// build/browser-journey.json; every scenario is recorded, pass or fail.
import { test } from "@playwright/test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "../..");
const pem = fs.readFileSync(path.join(ROOT, "build/test-pki/localhost.pem"));
const spki = crypto
  .createHash("sha256")
  .update(
    new crypto.X509Certificate(pem).publicKey.export({
      type: "spki",
      format: "der",
    }),
  )
  .digest("base64");

const QUERY_APP = process.env.QUERY_APP ?? "https://localhost:18080";
const FORM_APP = process.env.FORM_APP ?? "https://localhost:18081";
const SHORT_APP = process.env.SHORT_APP ?? "https://localhost:18082";
const ISSUER = "https://localhost:18443/realms/warden";

test.use({
  channel: "chrome",
  headless: true,
  launchOptions: { args: [`--ignore-certificate-errors-spki-list=${spki}`] },
});

async function keycloakLogin(page, user = "alice") {
  await page.waitForSelector("#kc-form-login", { timeout: 15000 });
  await page.fill("#username", user);
  await page.fill("#password", `${user}-disposable`);
  await page.click("#kc-login");
}

async function signIn(context, app = QUERY_APP, user = "alice") {
  const page = await context.newPage();
  let callback = null;
  page.on("request", (r) => {
    if (r.url().startsWith(`${app}/callback`))
      callback = { url: r.url(), method: r.method(), body: r.postData() };
  });
  await page.goto(`${app}/login`);
  await keycloakLogin(page, user);
  await page.waitForURL(`${app}/`, { timeout: 15000 });
  return { page, callback };
}

test("query login shows verified identity and custom claim", async ({
  context,
}) => {
  const { page } = await signIn(context);
  const email = await page.textContent("#email");
  const department = await page.textContent("#department");
  const issuer = await page.textContent("#issuer");
  assert.ok(email === "alice@example.test", `email ${email}`);
  assert.ok(department === "platform", `department ${department}`);
  assert.ok(issuer === ISSUER, `issuer ${issuer}`);
  const cookies = await context.cookies();
  const binding = cookies.find((c) => c.name === "__Host-warden_binding");
  const session = cookies.find((c) => c.name === "__Host-warden_session");
  assert.ok(
    binding?.httpOnly && binding?.secure && binding?.sameSite === "Lax",
    `binding cookie ${JSON.stringify(binding)}`,
  );
  assert.ok(
    session?.httpOnly && session?.secure,
    `session cookie ${JSON.stringify(session)}`,
  );
  return { email, department };
});

test("replayed callback is rejected", async ({ context }) => {
  const { page, callback } = await signIn(context);
  assert.ok(callback?.method === "GET", "callback captured");
  const response = await page.goto(callback.url);
  const body = await page.textContent("body");
  assert.ok(
    response.status() === 401 &&
      body.includes("the login was already completed"),
    `status ${response.status()} ${body}`,
  );
  return { status: response.status() };
});

test("refresh rotates the access token", async ({ context }) => {
  const { page } = await signIn(context);
  const before = await page.textContent("#token");
  await page.click("#refresh");
  const outcome = await page.textContent("#refresh-outcome");
  assert.ok(outcome === "completed", `refresh ${outcome}`);
  await page.goto(`${QUERY_APP}/`);
  const after = await page.textContent("#token");
  assert.ok(before !== after, `token fingerprint ${before} -> ${after}`);
  await page.click("#refresh");
  assert.ok(
    (await page.textContent("#refresh-outcome")) === "completed",
    "second refresh",
  );
  return { refreshes: 2 };
});

test("simultaneous tabs complete independently", async ({ context }) => {
  const a = await context.newPage();
  const b = await context.newPage();
  await a.goto(`${QUERY_APP}/login`);
  await b.goto(`${QUERY_APP}/login`);
  await a.waitForSelector("#kc-form-login");
  await b.waitForSelector("#kc-form-login");
  await keycloakLogin(b, "bob");
  await b.waitForURL(`${QUERY_APP}/`, { timeout: 15000 });
  // Tab A's Keycloak form belongs to the same browser; Keycloak may reuse the
  // SSO session. Either way tab A's own transaction must complete.
  await a.reload();
  if (await a.$("#kc-form-login")) await keycloakLogin(a, "bob");
  await a.waitForURL(`${QUERY_APP}/`, { timeout: 15000 });
  const emailA = await a.textContent("#email");
  const emailB = await b.textContent("#email");
  assert.ok(
    emailA === "bob@example.test" && emailB === "bob@example.test",
    `${emailA} ${emailB}`,
  );
  return { emailA, emailB };
});

test("provider denial is reported and consumes the login", async ({
  context,
}) => {
  const page = await context.newPage();
  let auth = null;
  page.on("request", (r) => {
    if (r.url().startsWith(`${ISSUER}/protocol/openid-connect/auth`))
      auth = new URL(r.url());
  });
  await page.goto(`${QUERY_APP}/login`);
  await page.waitForSelector("#kc-form-login");
  const state = auth.searchParams.get("state");
  const denial =
    `${QUERY_APP}/callback?` +
    new URLSearchParams({ error: "access_denied", state, iss: ISSUER });
  const first = await page.goto(denial);
  const firstBody = await page.textContent("body");
  const second = await page.goto(denial);
  const secondBody = await page.textContent("body");
  assert.ok(
    first.status() === 401 &&
      firstBody.includes("the provider denied the login"),
    firstBody,
  );
  assert.ok(
    second.status() === 401 &&
      secondBody.includes("the login was already completed"),
    secondBody,
  );
  return null;
});

test("callback without the browser binding does not consume the login", async ({
  context,
  browser,
}) => {
  const page = await context.newPage();
  let callbackUrl = null;
  // Hold the callback in this browser (CDP Fetch pauses redirect hops too);
  // replay it from a browser without the binding cookie first.
  const cdp = await context.newCDPSession(page);
  await cdp.send("Fetch.enable", {
    patterns: [{ urlPattern: `${QUERY_APP}/callback*` }],
  });
  cdp.on("Fetch.requestPaused", (event) => {
    callbackUrl = event.request.url;
    cdp
      .send("Fetch.failRequest", {
        requestId: event.requestId,
        errorReason: "Aborted",
      })
      .catch(() => {});
  });
  await page.goto(`${QUERY_APP}/login`);
  await keycloakLogin(page);
  await page.waitForTimeout(1000);
  assert.ok(callbackUrl, "callback captured");
  const other = await browser.newContext();
  const foreign = await other.newPage();
  const rejected = await foreign.goto(callbackUrl);
  const rejectedBody = await foreign.textContent("body");
  await other.close();
  assert.ok(
    rejected.status() === 400 &&
      rejectedBody.includes("browser binding cookie missing"),
    rejectedBody,
  );
  await cdp.send("Fetch.disable");
  await page.goto(callbackUrl);
  await page.waitForURL(`${QUERY_APP}/`, { timeout: 15000 });
  assert.ok(
    (await page.textContent("#email")) === "alice@example.test",
    "legitimate browser completes",
  );
  return null;
});

test("expired login is rejected", async ({ context }) => {
  const page = await context.newPage();
  await page.goto(`${SHORT_APP}/login`);
  await page.waitForSelector("#kc-form-login");
  await page.waitForTimeout(3500);
  await keycloakLogin(page);
  await page.waitForLoadState("load");
  const body = await page.textContent("body");
  assert.ok(body.includes("the login expired"), body);
  return null;
});

test("form_post login with SameSite=None binding", async ({ context }) => {
  const { page, callback } = await signIn(context, FORM_APP);
  assert.ok(
    callback?.method === "POST",
    `callback ${JSON.stringify(callback?.method)}`,
  );
  const binding = (await context.cookies()).find(
    (c) => c.name === "__Host-warden_binding",
  );
  assert.ok(
    binding?.sameSite === "None" && binding?.secure,
    `binding ${JSON.stringify(binding)}`,
  );
  assert.ok(
    (await page.textContent("#email")) === "alice@example.test",
    "email",
  );
  return null;
});

test("logout ends local and provider sessions", async ({ context }) => {
  const { page } = await signIn(context);
  await page.click("#logout");
  await page.waitForURL(
    (url) => url.href.startsWith(`${QUERY_APP}/logged-out`),
    { timeout: 15000 },
  );
  assert.ok(
    new URL(page.url()).searchParams.get("state"),
    "logout state returned",
  );
  await page.goto(`${QUERY_APP}/`);
  assert.ok(await page.$("#login"), "signed out locally");
  // The provider session ended: login shows the Keycloak form again.
  await page.goto(`${QUERY_APP}/login`);
  await page.waitForSelector("#kc-form-login", { timeout: 15000 });
  return null;
});
