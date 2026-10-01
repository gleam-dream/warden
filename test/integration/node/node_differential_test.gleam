//// Gate V4: the same scenario corpus through raw oidcc and through Warden,
//// each on its own transaction and authorization code (codes are never sent
//// to two implementations). Every disagreement must be a documented,
//// deliberate Warden policy.

import gleam/list
import gleam/string
import integration/node/node_warden_test.{attempt, basic, corpus, outcome}
import warden_test_support as support

@external(erlang, "node_raw_ffi", "raw_login")
fn raw_login(mutation: String, unused: Nil) -> String

/// Scenarios where Warden deliberately differs from raw oidcc defaults.
const stricter = [
  // oidcc default `trusted_audiences: any` accepts extra audiences; Warden
  // requires exactly the client (design §3.3).
  #("extra_aud", "IdTokenAudienceMismatch"),
  // oidcc accepts a token response without an ID token; Warden requires one
  // for login (design §3.3).
  #("omit", "MissingIdToken"),
]

pub fn raw_backend_differential_test() {
  support.node_reset()
  let client = basic()
  let scenarios =
    corpus()
    |> list.map(fn(c) { c.0 })
    |> list.append(["omit"])
  let rows =
    list.map(scenarios, fn(scenario) {
      let raw = raw_login(scenario, Nil)
      case scenario {
        "omit" ->
          support.node_next("authorization_code", [support.NodeOmitIdToken])
        _ ->
          support.node_next("authorization_code", [
            support.NodeIdToken(scenario),
          ])
      }
      let warden = outcome(attempt(client, "alice"))
      #(scenario, raw, warden)
    })
  // Agreement: raw accepts exactly when Warden completes, except for the
  // documented stricter policies.
  let disagreements =
    list.filter(rows, fn(row) {
      let #(_, raw, warden) = row
      { raw == "accepted" } != { warden == "ok" }
    })
    |> list.map(fn(row) { #(row.0, row.2) })
  assert disagreements == stricter
  // Raw oidcc accepts those scenarios; Warden rejects them.
  list.each(stricter, fn(s) {
    let assert Ok(#(_, raw, _)) = list.find(rows, fn(r) { r.0 == s.0 })
    assert raw == "accepted"
  })
  // Keep a readable record in the test output.
  list.each(rows, fn(row) {
    support.print(string.join([row.0, row.1, row.2], " | "))
  })
}
