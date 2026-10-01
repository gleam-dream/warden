// expect: Unknown module value
import warden

pub fn main(identity: warden.VerifiedIdentity) {
  warden.Session(identity: identity, reference: "r", revision: 1, provider: "p")
}
