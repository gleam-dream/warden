# Refresh custody preserves uncertain effects and publication evidence

<a id="adr-0005"></a>

- **Decision:** refresh permission belongs to custody, not a copyable Session or recovery token. Only a fresh confirmed reservation dispatches. Possible transmission and invalid success quarantine the predecessor; publication recovery repeats already received material without another provider call.
- **History:** D22/D23 replaced process-local death detection with durable leases and unified access/refresh results in `5a7da27` (2026-10-03). Waiting callers no longer duplicate application polling or dispatch authority. `RefreshReservationRecovery` was removed; quarantine became retained custody state.
- **Alternatives:** releasing an expired lease might resend a rotated token; treating every transport error as retryable loses possible-send evidence. Making every caller manage a token bag/mutex would not preserve multi-node single-flight or uncertain publication.
- **Lease consequence:** outstanding lease expiry becomes Orphaned. Its own delayed publication remains acceptable; late no-send cannot release it. Lease is request timeout plus two store timeouts plus one second, rather than a claim that killing a process reverses the provider effect.
- **Access policy:** a stale view uses current custody revision. Waiters have a separate bounded wait. A margin-triggered undecided refresh may use a still-unexpired token; forced refresh, quarantine and revocation never use that fallback.
- **Continuity:** missing refreshed ID token preserves identity without a new authentication event. Present claims retain original issuer/subject/audience/party/nonce/authentication time. Omitted refresh token retains it; explicit replacement supersedes it. Returned scope sets must remain unchanged under the selected current profile.
- **Unresolved:** broader scope/resource response profiles and operator reconciliation need explicit authority contracts. An uncertain reservation cannot become a redispatch merely because a caller asks to recover.
- **Provenance:** [D6/D19/D22/D23](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/decisions.md); retained `custody.gleam`, refresh continuity/lease/publication tests, node lost-response oracle and consumer recovery cases.
