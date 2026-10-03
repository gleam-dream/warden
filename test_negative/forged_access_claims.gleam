// expect: Unknown module value
import warden/resource

pub fn main() {
  resource.AccessClaims(issuer: "https://evil", subject: "admin")
}
