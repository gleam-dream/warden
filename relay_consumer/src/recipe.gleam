// snips-start: relay-verifier
import gleam/option.{type Option, None, Some}
import relay/authorization.{type Attestation, type Verifier}
import warden
import warden/resource

pub type Principal {
  Principal(subject: String, client_id: Option(String), scopes: List(String))
}

/// Local RFC 9068 validation: no provider request per token. A token for
/// another resource gets Relay's "issued for another resource" challenge.
pub fn jwt_verifier(validator: resource.Validator) -> Verifier(Principal) {
  let verify =
    resource.verifier(
      validator,
      authorization.token_value,
      attest,
      on_error: refuse,
    )
  use token, _correlation <- authorization.verifier("warden-jwt")
  verify(token)
}

fn refuse(kind: resource.ErrorKind) -> authorization.VerificationError {
  case kind {
    resource.Rejected | resource.Forbidden -> authorization.BearerRejected
    resource.WrongAudience -> authorization.IssuedForAnotherResource
    resource.Unavailable -> authorization.VerifierUnavailable
  }
}

fn attest(claims: resource.AccessClaims) -> Attestation(Principal) {
  let scopes = resource.scopes(claims)
  authorization.attestation(
    Principal(resource.subject(claims), resource.client_id(claims), scopes),
    resource.audiences(claims),
    scopes,
  )
}

/// RFC 7662 introspection: one provider request per token, so a revoked
/// token is refused at once. The request's correlation tags the provider
/// call, so it joins the MCP request in telemetry.
pub fn introspection_verifier(client: warden.Client) -> Verifier(Principal) {
  use token, correlation <- authorization.verifier("warden-introspection")
  let client = warden.with_correlation(client, correlation)
  case warden.introspect(client, authorization.token_value(token)) {
    Ok(warden.ActiveToken(warden.TokenInfo(subject: Some(subject), ..) as info)) ->
      Ok(authorization.attestation(
        Principal(subject, info.client_id, info.scopes),
        info.audiences,
        info.scopes,
      ))
    Ok(warden.ActiveToken(warden.TokenInfo(subject: None, ..))) ->
      Error(authorization.VerifierUnmapped)
    Ok(warden.InactiveToken) | Error(warden.IntrospectionTokenTooLarge) ->
      Error(authorization.BearerRejected)
    Error(warden.IntrospectionNotSupported)
    | Error(warden.IntrospectionFailed(_)) ->
      Error(authorization.VerifierUnavailable)
  }
}
// snips-end: relay-verifier
