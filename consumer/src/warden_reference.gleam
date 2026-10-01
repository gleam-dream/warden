//// Warden reference relying party.
////
//// Configuration comes from the environment; every Warden call uses public
//// imports. Run with `gleam run` inside `consumer/`:
////
//// | Variable | Meaning |
//// | --- | --- |
//// | `WARDEN_ISSUER` | Provider issuer URL |
//// | `WARDEN_CLIENT_ID`, `WARDEN_CLIENT_SECRET` | Client credentials (secret optional) |
//// | `WARDEN_AUTH` | `basic` (default), `post`, `jwt`, `public` |
//// | `WARDEN_BASE_URL` | This app's external origin, e.g. `https://localhost:18080` |
//// | `WARDEN_RESPONSE_MODE` | `query` (default) or `form_post` |
//// | `WARDEN_SCOPES` | Space-separated extra scopes |
//// | `WARDEN_CA_FILE` | PEM trust anchors (default: system trust) |
//// | `WARDEN_ALLOW_LOOPBACK` | `1` to allow loopback providers (tests only) |
//// | `WARDEN_TLS_CERT`, `WARDEN_TLS_KEY` | Serve HTTPS with these files |
//// | `WARDEN_LOGIN_LIFETIME` | Pending-login lifetime in seconds (default 600) |
//// | `WARDEN_ASSUME_UNADVERTISED_S256` | `1` to accept a provider that omits PKCE metadata (confidential clients) |
//// | `PORT` | Listening port (default 18080) |

import envoy
import gleam/dynamic.{type Dynamic}
import gleam/erlang/atom
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import mist
import simplifile
import sinal
import warden
import warden/config
import warden/observation
import warden_reference/web
import wisp
import wisp/wisp_mist

pub fn main() -> Nil {
  let env = fn(name, default) { envoy.get(name) |> result.unwrap(default) }
  let base_url = env("WARDEN_BASE_URL", "https://localhost:18080")
  let response_mode = case env("WARDEN_RESPONSE_MODE", "query") {
    "form_post" -> config.FormPost
    _ -> config.Query
  }
  let secret = config.secret(env("WARDEN_CLIENT_SECRET", ""))
  let authentication = case env("WARDEN_AUTH", "basic") {
    "post" -> config.ClientSecretPost(secret)
    "jwt" -> config.ClientSecretJwt(secret)
    "public" -> config.PublicClient
    _ -> config.ClientSecretBasic(secret)
  }
  let settings =
    config.new(
      issuer: env("WARDEN_ISSUER", ""),
      client_id: env("WARDEN_CLIENT_ID", ""),
      redirect_uri: base_url <> "/callback",
      authentication:,
    )
    |> config.with_scopes(
      string.split(env("WARDEN_SCOPES", "profile email"), " ")
      |> list.filter(fn(s) { s != "" }),
    )
    |> config.with_response_mode(response_mode)
    |> config.with_login_lifetime(
      env("WARDEN_LOGIN_LIFETIME", "600") |> int.parse |> result.unwrap(600),
    )
  let settings = case envoy.get("WARDEN_CA_FILE") {
    Ok(path) -> {
      let assert Ok(pem) = simplifile.read(path)
      config.with_trust(settings, config.TrustAnchorsPem(pem))
    }
    Error(Nil) -> settings
  }
  // WARDEN_ASSUME_UNADVERTISED_S256=1 accepts a provider whose metadata
  // omits code_challenge_methods_supported (decision D7), such as the
  // OpenID conformance suite's test OP.
  let settings = case env("WARDEN_ASSUME_UNADVERTISED_S256", "") {
    "1" ->
      config.with_pkce_advertisement(
        settings,
        config.AssumeS256WhenUnadvertised,
      )
    _ -> settings
  }
  let settings = case env("WARDEN_ALLOW_LOOPBACK", "") {
    "1" -> config.with_destinations(settings, config.AllowLoopbackForTesting)
    _ -> settings
  }
  let validated = case config.validate(settings) {
    Ok(validated) -> validated
    Error(errors) ->
      panic as { "invalid configuration: " <> string.inspect(errors) }
  }
  log_outbound_requests()
  let started = warden.start(validated)
  let client = case started {
    Ok(client) -> client
    Error(error) ->
      panic as { "warden did not start: " <> string.inspect(error) }
  }
  let context =
    web.Context(
      client:,
      issuer: config.issuer(validated),
      response_mode:,
      login_lifetime: config.login_lifetime_seconds(validated),
      post_logout_redirect_uri: base_url <> "/logged-out",
    )
  let port = env("PORT", "18080") |> int.parse |> result.unwrap(18_080)
  let server =
    wisp_mist.handler(web.handle(_, context), wisp.random_string(64))
    |> mist.new
    |> mist.bind("127.0.0.1")
    |> mist.port(port)
  let server = case envoy.get("WARDEN_TLS_CERT"), envoy.get("WARDEN_TLS_KEY") {
    Ok(cert), Ok(key) -> mist.with_tls(server, certfile: cert, keyfile: key)
    _, _ -> server
  }
  let assert Ok(_) = mist.start(server)
  io.println("warden reference RP listening on " <> base_url)
  process.sleep_forever()
}

/// One log line per outbound Warden request, from the typed observation
/// event. The event holds no secrets, so it is safe to print whole.
fn log_outbound_requests() -> Nil {
  // Attaching needs the telemetry application running; before
  // `warden.start` that is the application's job.
  let assert True = start_telemetry()
  let assert Ok(id) = sinal.handler_id("warden-reference-http")
  let assert Ok(_) =
    sinal.observe(id, observation.http_request(), fn(measurements, request) {
      let outcome = case request.outcome {
        observation.Status(code) -> int.to_string(code)
        observation.Failed(sent: True, class:) -> "failed after send: " <> class
        observation.Failed(sent: False, class:) -> "not sent: " <> class
      }
      let method = case request.method {
        observation.Get -> "GET"
        observation.Post -> "POST"
      }
      io.println(
        "warden http "
        <> method
        <> " "
        <> request.host
        <> request.path
        <> " -> "
        <> outcome
        <> " ("
        <> int.to_string(measurements.duration_ms)
        <> " ms)",
      )
    })
  Nil
}

fn start_telemetry() -> Bool {
  case ensure_all_started(atom.create("telemetry")) {
    Ok(_) -> True
    Error(_) -> False
  }
}

@external(erlang, "application", "ensure_all_started")
fn ensure_all_started(application: atom.Atom) -> Result(Dynamic, Dynamic)
