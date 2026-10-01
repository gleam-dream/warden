// expect: Unknown module value
import warden

pub fn main() {
  warden.AccessToken(reveal: fn() { "token" }, token_type: "Bearer")
}
