//// Browser-facing protections of the reference relying party. Applications
//// copying it should keep all of them (docs/APPLICATION-RESPONSIBILITIES.md).

import gleam/http/cookie
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import wisp.{type Request, type Response}

/// `__Host-` cookies must be `Secure`, have `Path=/` and no `Domain`, so a
/// sibling subdomain or a plaintext response cannot plant them. Warden sets
/// its own browser-binding cookie (`warden.login_response`).
pub const session_cookie = "__Host-warden_session"

/// Attributes of the session cookie.
pub fn session_attributes(max_age: Int) -> cookie.Attributes {
  cookie.Attributes(
    max_age: Some(max_age),
    domain: None,
    path: Some("/"),
    secure: True,
    http_only: True,
    same_site: Some(cookie.Lax),
  )
}

/// True when a state-changing request comes from this application's own
/// pages: `Sec-Fetch-Site: same-origin` or an `Origin` equal to `origin`.
/// Requests without either signal are refused.
pub fn same_origin(request: Request, origin: String) -> Bool {
  case
    request.get_header(request, "sec-fetch-site"),
    request.get_header(request, "origin")
  {
    Ok("same-origin"), _ -> True
    Ok(_), _ -> False
    Error(Nil), Ok(value) -> value == origin
    Error(Nil), Error(Nil) -> False
  }
}

/// The signed session cookie value: the custody reference and its issue
/// time, so the server enforces the session lifetime itself.
pub fn session_value(reference: String, issued_at issued_at: Int) -> String {
  reference <> "." <> int.to_string(issued_at)
}

pub fn read_session_value(
  value: String,
  now now: Int,
  max_age max_age: Int,
) -> Result(String, Nil) {
  // The opaque custody reference can contain periods. Only the final
  // delimiter separates the issue time in the verified cookie payload.
  case list.reverse(string.split(value, ".")) {
    [issued, reference, ..prefix] ->
      case int.parse(issued) {
        Ok(issued_at) if now - issued_at <= max_age && issued_at <= now ->
          Ok([reference, ..prefix] |> list.reverse |> string.join("."))
        _ -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

/// Headers for every response: no caching of pages with personal data or
/// callback URLs, no framing, no referrer leakage, HTTPS only. No
/// `form-action`: browsers apply it to the redirect after a form post, which
/// would block logout's redirect to the provider.
pub fn security_headers(response: Response) -> Response {
  response
  |> wisp.set_header("cache-control", "no-store")
  |> wisp.set_header("referrer-policy", "no-referrer")
  |> wisp.set_header("x-content-type-options", "nosniff")
  |> wisp.set_header(
    "content-security-policy",
    "default-src 'none'; frame-ancestors 'none'",
  )
  |> wisp.set_header(
    "strict-transport-security",
    "max-age=31536000; includeSubDomains",
  )
}
