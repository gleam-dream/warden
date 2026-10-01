// Real-browser journey through the Warden reference RP and the pinned
// Keycloak (`scripts/browser-journey`). Chrome is the installed Google Chrome,
// driven by playwright-core. Chrome accepts only the disposable test
// certificate's public key (`--ignore-certificate-errors-spki-list`); no other
// certificate check is relaxed. Results are written to
// build/browser-journey.json; every scenario is recorded, pass or fail.
import { chromium } from "playwright-core";
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

const browser = await chromium.launch({
  channel: "chrome",
  headless: true,
  args: [`--ignore-certificate-errors-spki-list=${spki}`],
});
const results = [];

async function scenario(name, fn) {
  const context = await browser.newContext();
  try {
    const detail = await fn(context);
    results.push({ name, result: "pass", detail: detail ?? null });
  } catch (error) {
    results.push({
      name,
      result: "fail",
      detail: String(error?.message ?? error),
    });
  } finally {
    await context.close();
  }
}

async function keycloakLogin(page, user = "alice") {
  await page.waitForSelector("#kc-form-login", { timeout: 15000 });
  await page.fill("#username", user);
  await page.fill("#password", `${user}-disposable`);
  await page.click("#kc-login");
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
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

await scenario(
  "query login shows verified identity and custom claim",
  async (context) => {
    const { page } = await signIn(context);
    const email = await page.textContent("#email");
    const department = await page.textContent("#department");
    const issuer = await page.textContent("#issuer");
    expect(email === "alice@example.test", `email ${email}`);
    expect(department === "platform", `department ${department}`);
    expect(issuer === ISSUER, `issuer ${issuer}`);
    const cookies = await context.cookies();
    const binding = cookies.find((c) => c.name === "__Host-warden_binding");
    const session = cookies.find((c) => c.name === "__Host-warden_session");
    expect(
      binding?.httpOnly && binding?.secure && binding?.sameSite === "Lax",
      `binding cookie ${JSON.stringify(binding)}`,
    );
    expect(
      session?.httpOnly && session?.secure,
      `session cookie ${JSON.stringify(session)}`,
    );
    return { email, department };
  },
);

await scenario("replayed callback is rejected", async (context) => {
  const { page, callback } = await signIn(context);
  expect(callback?.method === "GET", "callback captured");
  const response = await page.goto(callback.url);
  const body = await page.textContent("body");
  expect(
    response.status() === 401 && body.includes("already used"),
    `status ${response.status()} ${body}`,
  );
  return { status: response.status() };
});

await scenario(
  "refresh rotates tokens and advances the revision",
  async (context) => {
    const { page } = await signIn(context);
    await page.click("#refresh");
    const outcome = await page.textContent("#refresh-outcome");
    expect(outcome === "completed", `refresh ${outcome}`);
    await page.goto(`${QUERY_APP}/`);
    const revision = await page.textContent("#revision");
    expect(revision === "2", `revision ${revision}`);
    await page.click("#refresh");
    expect(
      (await page.textContent("#refresh-outcome")) === "completed",
      "second refresh",
    );
    return { revision: 3 };
  },
);

await scenario("simultaneous tabs complete independently", async (context) => {
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
  expect(
    emailA === "bob@example.test" && emailB === "bob@example.test",
    `${emailA} ${emailB}`,
  );
  return { emailA, emailB };
});

await scenario(
  "provider denial is reported and consumes the login",
  async (context) => {
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
    expect(
      first.status() === 401 && firstBody.includes("AccessDenied"),
      firstBody,
    );
    expect(
      second.status() === 401 && secondBody.includes("already used"),
      secondBody,
    );
    return null;
  },
);

await scenario(
  "callback without the browser binding does not consume the login",
  async (context) => {
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
    expect(callbackUrl, "callback captured");
    const other = await browser.newContext();
    const foreign = await other.newPage();
    const rejected = await foreign.goto(callbackUrl);
    const rejectedBody = await foreign.textContent("body");
    await other.close();
    expect(
      rejected.status() === 400 &&
        rejectedBody.includes("BrowserBindingMissing"),
      rejectedBody,
    );
    await cdp.send("Fetch.disable");
    await page.goto(callbackUrl);
    await page.waitForURL(`${QUERY_APP}/`, { timeout: 15000 });
    expect(
      (await page.textContent("#email")) === "alice@example.test",
      "legitimate browser completes",
    );
    return null;
  },
);

await scenario("expired login is rejected", async (context) => {
  const page = await context.newPage();
  await page.goto(`${SHORT_APP}/login`);
  await page.waitForSelector("#kc-form-login");
  await page.waitForTimeout(3500);
  await keycloakLogin(page);
  await page.waitForLoadState("load");
  const body = await page.textContent("body");
  expect(body.includes("took too long"), body);
  return null;
});

await scenario(
  "form_post login with SameSite=None binding",
  async (context) => {
    const { page, callback } = await signIn(context, FORM_APP);
    expect(
      callback?.method === "POST",
      `callback ${JSON.stringify(callback?.method)}`,
    );
    const binding = (await context.cookies()).find(
      (c) => c.name === "__Host-warden_binding",
    );
    expect(
      binding?.sameSite === "None" && binding?.secure,
      `binding ${JSON.stringify(binding)}`,
    );
    expect(
      (await page.textContent("#email")) === "alice@example.test",
      "email",
    );
    return null;
  },
);

await scenario("logout ends local and provider sessions", async (context) => {
  const { page } = await signIn(context);
  await page.click("#logout");
  await page.waitForURL(
    (url) => url.href.startsWith(`${QUERY_APP}/logged-out`),
    { timeout: 15000 },
  );
  expect(
    new URL(page.url()).searchParams.get("state"),
    "logout state returned",
  );
  await page.goto(`${QUERY_APP}/`);
  expect(await page.$("#login"), "signed out locally");
  // The provider session ended: login shows the Keycloak form again.
  await page.goto(`${QUERY_APP}/login`);
  await page.waitForSelector("#kc-form-login", { timeout: 15000 });
  return null;
});

await browser.close();
fs.mkdirSync(path.join(ROOT, "build"), { recursive: true });
fs.writeFileSync(
  path.join(ROOT, "build/browser-journey.json"),
  JSON.stringify(
    {
      chrome: "installed Google Chrome",
      results,
    },
    null,
    2,
  ),
);
for (const r of results)
  console.log(
    `${r.result.toUpperCase()}  ${r.name}${r.result === "fail" ? ` — ${r.detail}` : ""}`,
  );
process.exit(results.every((r) => r.result === "pass") ? 0 : 1);
