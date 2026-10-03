//// R9: every error type has a description and a caller action; uncertain
//// outcomes never map to a plain retry. And the follow-up: HTTP Gun's own
//// connect, pool and idle bounds stay separate from the request timeout.

import gleam/list
import gleam/string
import http_gun/internal/settings as gun_settings
import warden
import warden/config
import warden/internal/transport
import warden/resource
import warden/store

pub fn every_login_error_describes_itself_and_has_an_action_test() {
  let errors = [
    warden.InvalidLoginOption(warden.InvalidMaxAge),
    warden.LoginNotConfigured,
    warden.LoginProviderUnavailable(warden.ProviderNotReady),
    warden.LoginProviderIncompatible([warden.NoS256]),
    warden.LoginStoreUnavailable,
    warden.TooManyPendingLogins,
    warden.CallbackMalformed(warden.MissingState),
    warden.CallbackRejected(warden.BrowserBindingMismatch),
    warden.LoginExpired,
    warden.LoginReplayed,
    warden.LoginChanged,
    warden.TransactionStoreUnavailable,
    warden.LoginRecordUnreadable,
    warden.ProviderDenied(warden.AccessDenied),
    warden.ProviderUnavailableBeforeExchange(warden.ProviderNotReady),
    warden.ExchangeRejected(warden.InvalidGrant),
    warden.ExchangeOutcomeUnknown,
    warden.IdentityRejected(warden.NonceMismatch),
    warden.LoginTimedOut,
    warden.RecoveryForeign,
    warden.RecoveryEnded,
    warden.RecoveryExpired,
  ]
  list.each(errors, fn(error) {
    assert warden.describe_login_error(error) != ""
    let _ = warden.login_error_action(error)
  })
  assert warden.login_error_action(warden.CallbackMalformed(warden.MissingCode))
    == warden.RejectRequest
  assert warden.login_error_action(warden.ExchangeOutcomeUnknown)
    == warden.Reauthenticate
  assert warden.login_error_action(warden.ExchangeRejected(warden.InvalidClient))
    == warden.FixConfiguration
}

pub fn every_session_error_describes_itself_and_has_an_action_test() {
  let errors = [
    warden.SessionNotFound,
    warden.SessionLost,
    warden.SessionForeign,
    warden.SessionStoreUnavailable,
    warden.SessionRecordUnreadable,
    warden.SessionHasNoAccessToken,
    warden.RefreshTokenUnavailable,
    warden.RefreshRevoked,
    warden.RefreshRejected(warden.InvalidScope),
    warden.RefreshNotSent(warden.ProviderNotReady),
    warden.RefreshQuarantined(warden.ProviderOutcomeUnknown),
    warden.RefreshQuarantined(warden.RefresherLost),
    warden.RefreshQuarantined(
      warden.ResponseRejected(
        warden.RefreshedIdTokenInvalid(warden.MissingClaim("sub")),
      ),
    ),
    warden.RefreshWaitTimedOut,
    warden.RefreshRecoveryForeign,
  ]
  list.each(errors, fn(error) {
    assert warden.describe_session_error(error) != ""
  })
  // An uncertain refresh is never "try the same request again".
  assert warden.session_error_action(warden.RefreshQuarantined(
      warden.ProviderOutcomeUnknown,
    ))
    == warden.Reauthenticate
  assert warden.session_error_action(warden.RefreshRevoked)
    == warden.Reauthenticate
  assert warden.session_error_action(warden.RefreshNotSent(
      warden.ProviderNotReady,
    ))
    == warden.RetryLater
  assert warden.session_error_action(warden.SessionStoreUnavailable)
    == warden.RetryLater
}

pub fn other_errors_describe_themselves_test() {
  assert warden.describe_start_error(warden.StartupTimedOut) != ""
  assert string.contains(
    warden.describe_start_error(warden.InvalidConfig([config.InvalidIssuer])),
    "issuer",
  )
  assert warden.describe_provider_failure(warden.TransportFailure(
      evidence: warden.MaybeSent,
      reason: warden.Timeout,
    ))
    == "timeout (may have been sent)"
  assert warden.describe_userinfo_error(warden.UserinfoNotSupported) != ""
  assert warden.describe_client_credentials_error(
      warden.ClientCredentialsOutcomeUnknown,
    )
    != ""
  assert warden.describe_introspection_error(warden.IntrospectionTokenTooLarge)
    != ""
  assert warden.describe_logout_error(warden.LogoutStoreUnavailable) != ""
  assert resource.describe_error(resource.AudienceMismatch) != ""
  assert store.describe_error(store.StoreFull) != ""
}

/// Follow-up (wave 3): the connect, pool-checkout, idle-read and idle
/// connection bounds are HTTP Gun's own (5 s, 5 s, 30 s, 60 s), not copies
/// of the request timeout.
pub fn http_gun_keeps_its_separate_bounds_test() {
  let policy =
    transport.Policy(
      ..transport.policy(transport.SystemTrust),
      timeout_ms: 20_000,
    )
  let gun = transport.gun_config(policy)
  assert gun.connect_timeout == 5000
  assert gun.pool_timeout == 5000
  assert gun.request_timeout == gun_settings.Within(20_000)
  assert gun.idle_timeout == gun_settings.Within(30_000)
  assert gun.connection_idle_timeout == 60_000
}
