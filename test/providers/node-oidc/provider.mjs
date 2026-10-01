// Disposable scriptable OpenID provider for Warden tests.
//
// node-oidc-provider supplies the real protocol behaviour; panva/jose supplies
// independent JOSE operations for the hostile ID-token corpus and for verifying
// the client assertions Warden sends. All keys are generated at startup and
// written only under build/test-pki. Nothing here is a production setting.
//
// Control API (test-only, same TLS listener):
//   POST /__control/reset
//   POST /__control/next   {grant, idToken?, omitIdToken?, status?, delayMs?, dropRefreshToken?}
//        applies once to the next token response of that grant type
//   GET  /__control/log    token-endpoint requests observed so far
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as jose from "jose";
import Provider from "oidc-provider";

const PORT = Number(process.env.PORT ?? 19443);
const ISS = `https://localhost:${PORT}`;
const PKI =
  process.env.PKI_DIR ??
  path.resolve(import.meta.dirname, "../../../build/test-pki");

// OP signing key (RS256) and an EC key the OP also publishes.
const opRsa = await jose.generateKeyPair("RS256", { extractable: true });
const opRsaJwk = {
  ...(await jose.exportJWK(opRsa.privateKey)),
  kid: "op-rs256",
  alg: "RS256",
  use: "sig",
};
const opRsaPublicPem = await jose.exportSPKI(opRsa.publicKey);
const opEc = await jose.generateKeyPair("ES256", { extractable: true });
const opEcJwk = {
  ...(await jose.exportJWK(opEc.privateKey)),
  kid: "op-es256",
  alg: "ES256",
  use: "sig",
};
// A key the OP never publishes, for unknown-kid and bad-signature cases.
const rogue = await jose.generateKeyPair("RS256", { extractable: true });

// Client keys for private_key_jwt; Warden tests read the private JWKs.
async function clientKey(alg, kid) {
  const pair = await jose.generateKeyPair(alg, { extractable: true });
  const priv = {
    ...(await jose.exportJWK(pair.privateKey)),
    kid,
    alg,
    use: "sig",
  };
  const pub = {
    ...(await jose.exportJWK(pair.publicKey)),
    kid,
    alg,
    use: "sig",
  };
  fs.writeFileSync(
    path.join(PKI, `node-client-${kid}.jwk.json`),
    JSON.stringify(priv),
  );
  return { pair, pub };
}
const clientEs = await clientKey("ES256", "client-es256");
const clientRs = await clientKey("RS256", "client-rs256");

const SECRET = "warden-node-disposable-secret-0123456789";
const redirectUris = [
  "https://localhost:1/callback",
  "https://localhost:18080/callback",
  "http://127.0.0.1:18080/callback",
  "http://localhost:18080/callback",
];
const postLogout = [
  "https://localhost:1/logged-out",
  "https://localhost:18080/logged-out",
  "http://127.0.0.1:18080/logged-out",
  "http://localhost:18080/logged-out",
];
const common = {
  redirect_uris: redirectUris,
  post_logout_redirect_uris: postLogout,
  response_types: ["code"],
  grant_types: ["authorization_code", "refresh_token", "client_credentials"],
};

const accounts = {
  alice: {
    sub: "alice-subject",
    email: "alice@example.test",
    email_verified: true,
    name: "Alice Tester",
    department: "platform",
  },
  bob: {
    sub: "bob-subject",
    email: "bob@example.test",
    email_verified: false,
    name: "Bob Tester",
  },
};

const provider = new Provider(ISS, {
  jwks: { keys: [opRsaJwk, opEcJwk] },
  clients: [
    {
      ...common,
      client_id: "warden-rp",
      client_secret: SECRET,
      token_endpoint_auth_method: "client_secret_basic",
    },
    {
      ...common,
      client_id: "warden-post",
      client_secret: SECRET,
      token_endpoint_auth_method: "client_secret_post",
    },
    {
      ...common,
      client_id: "warden-hs",
      client_secret: SECRET,
      token_endpoint_auth_method: "client_secret_jwt",
      token_endpoint_auth_signing_alg: "HS256",
    },
    {
      ...common,
      client_id: "warden-es",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: { keys: [clientEs.pub] },
    },
    {
      ...common,
      client_id: "warden-rs",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "RS256",
      jwks: { keys: [clientRs.pub] },
    },
    {
      ...common,
      client_id: "warden-es-id",
      client_secret: SECRET,
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: "ES256",
    },
  ],
  pkce: { required: () => true },
  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: true },
    introspection: { enabled: true },
    rpInitiatedLogout: { enabled: true },
    userinfo: { enabled: true },
  },
  claims: {
    openid: ["sub"],
    email: ["email", "email_verified"],
    profile: ["name", "department"],
  },
  scopes: ["openid", "email", "profile", "offline_access", "api"],
  findAccount: (ctx, sub) => {
    const account = Object.values(accounts).find((a) => a.sub === sub);
    return account && { accountId: sub, claims: () => account };
  },
  issueRefreshToken: async (ctx, client) =>
    client.grantTypeAllowed("refresh_token"),
  rotateRefreshToken: true,
  interactions: {
    url: (ctx, interaction) => `/interaction/${interaction.uid}`,
  },
  ttl: {
    AccessToken: 300,
    AuthorizationCode: 60,
    IdToken: 300,
    RefreshToken: 3600,
  },
});

// Test control state.
let pending = [];
let log = [];

// Headless interaction: approve as the account named by login_hint.
provider.use(async (ctx, next) => {
  const m = ctx.path.match(/^\/interaction\/([^/]+)$/);
  if (!m) return next();
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  const { prompt, params, session } = details;
  const name = params.login_hint ?? "alice";
  if (name === "deny") {
    return provider.interactionFinished(
      ctx.req,
      ctx.res,
      { error: "access_denied", error_description: "user denied" },
      { mergeWithLastSubmission: false },
    );
  }
  const accountId =
    session?.accountId ?? accounts[name]?.sub ?? accounts.alice.sub;
  const grant = details.grantId
    ? await provider.Grant.find(details.grantId)
    : new provider.Grant({ accountId, clientId: params.client_id });
  if (prompt.details.missingOIDCScope)
    grant.addOIDCScope(prompt.details.missingOIDCScope.join(" "));
  if (prompt.details.missingOIDCClaims)
    grant.addOIDCClaims(prompt.details.missingOIDCClaims);
  if (prompt.details.missingResourceScopes)
    for (const [r, s] of Object.entries(prompt.details.missingResourceScopes))
      grant.addResourceScope(r, s.join(" "));
  const grantId = await grant.save();
  await provider.interactionFinished(
    ctx.req,
    ctx.res,
    { login: { accountId }, consent: { grantId } },
    { mergeWithLastSubmission: false },
  );
});

// Record token requests and verify client assertions independently with jose.
provider.use(async (ctx, next) => {
  if (ctx.path !== "/token" || ctx.method !== "POST") return next();
  const entry = { at: Date.now() };
  await next();
  const params = ctx.oidc?.params ?? {};
  entry.grant_type = params.grant_type;
  entry.client_id = ctx.oidc?.client?.clientId;
  entry.status = ctx.status;
  if (params.client_assertion)
    entry.assertion = await verifyAssertion(
      params.client_assertion,
      entry.client_id,
    );
  log.push(entry);
  const idx = pending.findIndex((p) => p.grant === params.grant_type);
  if (idx >= 0 && ctx.status === 200) {
    const action = pending.splice(idx, 1)[0];
    entry.action = action;
    await applyAction(ctx, action);
  }
});

async function verifyAssertion(assertion, clientId) {
  const header = jose.decodeProtectedHeader(assertion);
  const opts = {
    issuer: clientId,
    subject: clientId,
    audience: [ISS, `${ISS}/token`],
    algorithms: ["ES256", "RS256", "HS256"],
  };
  try {
    let key;
    if (header.alg === "HS256") key = new TextEncoder().encode(SECRET);
    else if (clientId === "warden-es") key = clientEs.pair.publicKey;
    else key = clientRs.pair.publicKey;
    const { payload } = await jose.jwtVerify(assertion, key, opts);
    return {
      verified: true,
      alg: header.alg,
      kid: header.kid ?? null,
      jti: typeof payload.jti === "string",
      exp: payload.exp,
    };
  } catch (e) {
    return { verified: false, alg: header.alg, error: e.code };
  }
}

async function sign(claims, header, key) {
  return new jose.SignJWT(claims).setProtectedHeader(header).sign(key);
}

// Hostile ID-token corpus. Each case derives from the provider's real ID token
// so nonce, audience and times stay those of the current transaction.
async function mutateIdToken(idToken, kind, accessToken) {
  const claims = jose.decodeJwt(idToken);
  const now = Math.floor(Date.now() / 1000);
  const rs = { alg: "RS256", kid: "op-rs256" };
  switch (kind) {
    case "resign":
      return sign(claims, rs, opRsa.privateKey);
    case "es256":
      return sign(claims, { alg: "ES256", kid: "op-es256" }, opEc.privateKey);
    case "bad_signature": {
      const t = await sign({ ...claims, extra: "x" }, rs, opRsa.privateKey);
      const [h, , s] = t.split(".");
      return [h, jose.base64url.encode(JSON.stringify(claims)), s].join(".");
    }
    case "alg_none":
      return new jose.UnsecuredJWT(claims).encode();
    case "hs256_confusion":
      return sign(
        claims,
        { alg: "HS256", kid: "op-rs256" },
        new TextEncoder().encode(opRsaPublicPem),
      );
    case "hs256_client_secret":
      return sign(claims, { alg: "HS256" }, new TextEncoder().encode(SECRET));
    case "unknown_kid":
      return sign(
        claims,
        { alg: "RS256", kid: "rotated-unknown" },
        rogue.privateKey,
      );
    case "no_kid_wrong_key":
      return sign(claims, { alg: "RS256" }, rogue.privateKey);
    case "wrong_iss":
      return sign(
        { ...claims, iss: "https://evil.example" },
        rs,
        opRsa.privateKey,
      );
    case "wrong_aud":
      return sign({ ...claims, aud: "someone-else" }, rs, opRsa.privateKey);
    case "extra_aud":
      return sign(
        { ...claims, aud: [claims.aud, "someone-else"] },
        rs,
        opRsa.privateKey,
      );
    case "wrong_azp":
      return sign({ ...claims, azp: "someone-else" }, rs, opRsa.privateKey);
    case "expired":
      return sign(
        { ...claims, iat: now - 7200, exp: now - 3600 },
        rs,
        opRsa.privateKey,
      );
    case "nbf_future":
      return sign({ ...claims, nbf: now + 3600 }, rs, opRsa.privateKey);
    case "missing_sub": {
      const { sub, ...rest } = claims;
      return sign(rest, rs, opRsa.privateKey);
    }
    case "missing_iat": {
      const { iat, ...rest } = claims;
      return sign(rest, rs, opRsa.privateKey);
    }
    case "wrong_nonce":
      return sign({ ...claims, nonce: "attacker-nonce" }, rs, opRsa.privateKey);
    case "missing_nonce": {
      const { nonce, ...rest } = claims;
      return sign(rest, rs, opRsa.privateKey);
    }
    case "bad_at_hash":
      return sign(
        { ...claims, at_hash: jose.base64url.encode(crypto.randomBytes(16)) },
        rs,
        opRsa.privateKey,
      );
    case "good_at_hash": {
      const digest = crypto.createHash("sha256").update(accessToken).digest();
      return sign(
        { ...claims, at_hash: jose.base64url.encode(digest.subarray(0, 16)) },
        rs,
        opRsa.privateKey,
      );
    }
    case "changed_sub":
      return sign({ ...claims, sub: "someone-else" }, rs, opRsa.privateKey);
    case "changed_nonce":
      return sign({ ...claims, nonce: "changed-nonce" }, rs, opRsa.privateKey);
    case "changed_auth_time":
      return sign(
        { ...claims, auth_time: (claims.auth_time ?? now) - 1000 },
        rs,
        opRsa.privateKey,
      );
    case "encrypted_unsigned": {
      const enc = await jose.generateKeyPair("RSA-OAEP", { extractable: true });
      return new jose.EncryptJWT(claims)
        .setProtectedHeader({ alg: "RSA-OAEP", enc: "A128CBC-HS256" })
        .encrypt(enc.publicKey);
    }
    default:
      throw new Error(`unknown mutation ${kind}`);
  }
}

async function applyAction(ctx, action) {
  const body = ctx.body;
  if (action.idToken && body.id_token)
    body.id_token = await mutateIdToken(
      body.id_token,
      action.idToken,
      body.access_token,
    );
  if (action.omitIdToken) delete body.id_token;
  if (action.dropRefreshToken) delete body.refresh_token;
  if (action.scope !== undefined) body.scope = action.scope;
  if (action.status) ctx.status = action.status;
  if (action.delayMs) await new Promise((r) => setTimeout(r, action.delayMs));
}

function readJson(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data ? JSON.parse(data) : {}));
  });
}

const callback = provider.callback();
const server = https.createServer(
  {
    key: fs.readFileSync(path.join(PKI, "localhost.key")),
    cert: fs.readFileSync(path.join(PKI, "localhost.pem")),
  },
  async (req, res) => {
    if (req.url.startsWith("/__control/")) {
      const route = req.url.slice("/__control/".length);
      if (route === "reset") {
        pending = [];
        log = [];
      } else if (route === "next") pending.push(await readJson(req));
      else if (route === "log") {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify(log));
      }
      res.writeHead(204);
      return res.end();
    }
    return callback(req, res);
  },
);
server.listen(PORT, "127.0.0.1", () => console.log(`provider ready ${ISS}`));
