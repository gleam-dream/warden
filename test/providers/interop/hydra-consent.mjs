// Headless login/consent/logout app for Ory Hydra in Warden tests. It accepts
// every login as the disposable test user and grants the requested scopes.
import https from "node:https";
import fs from "node:fs";
import path from "node:path";

const PKI = path.resolve(import.meta.dirname, "../../../build/test-pki");
const ADMIN = "https://localhost:14445/admin/oauth2/auth/requests";

async function admin(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body && JSON.stringify(body),
  });
  return r.json();
}

https
  .createServer(
    {
      key: fs.readFileSync(path.join(PKI, "localhost.key")),
      cert: fs.readFileSync(path.join(PKI, "localhost.pem")),
    },
    async (req, res) => {
      const url = new URL(req.url, "https://localhost:14446");
      let redirect;
      if (url.pathname === "/login") {
        const challenge = url.searchParams.get("login_challenge");
        redirect = await admin(
          "PUT",
          `${ADMIN}/login/accept?login_challenge=${challenge}`,
          { subject: "alice-subject", remember: false },
        );
      } else if (url.pathname === "/consent") {
        const challenge = url.searchParams.get("consent_challenge");
        const consent = await admin(
          "GET",
          `${ADMIN}/consent?consent_challenge=${challenge}`,
        );
        redirect = await admin(
          "PUT",
          `${ADMIN}/consent/accept?consent_challenge=${challenge}`,
          {
            grant_scope: consent.requested_scope,
            grant_access_token_audience:
              consent.requested_access_token_audience,
            session: {
              id_token: { email: "alice@example.test", email_verified: true },
            },
          },
        );
      } else if (url.pathname === "/logout") {
        const challenge = url.searchParams.get("logout_challenge");
        redirect = await admin(
          "PUT",
          `${ADMIN}/logout/accept?logout_challenge=${challenge}`,
        );
      }
      if (redirect?.redirect_to) {
        res.writeHead(302, { location: redirect.redirect_to });
        return res.end();
      }
      res.writeHead(404);
      res.end();
    },
  )
  .listen(14446, "127.0.0.1");
