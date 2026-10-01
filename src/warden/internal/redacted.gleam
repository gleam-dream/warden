//// A value held behind a closure. `string.inspect`, `echo`, `io_lib:format`
//// and OTP crash reports print a closure as a function reference, never
//// its captured environment, so secret-bearing fields of public values
//// (credentials, bindings, session references, tokens, raw claims) do not
//// reach logs when an application prints a Warden value.
////
//// This does not protect against VM introspection (`sys:get_state`, remote
//// shells, crash dumps); see docs/APPLICATION-RESPONSIBILITIES.md.

pub opaque type Redacted(a) {
  Redacted(reveal: fn() -> a)
}

pub fn new(value: a) -> Redacted(a) {
  Redacted(fn() { value })
}

pub fn reveal(redacted: Redacted(a)) -> a {
  redacted.reveal()
}
