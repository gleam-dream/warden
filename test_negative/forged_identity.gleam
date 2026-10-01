// expect: Unknown module value
import gleam/dynamic
import warden

pub fn main() {
  warden.VerifiedIdentity(
    issuer: "https://idp",
    subject: "s",
    claims: dynamic.nil(),
  )
}
