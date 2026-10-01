// expect: Unknown module value
import gleam/dynamic
import warden

pub fn main() {
  warden.UserInfo(subject: "s", claims: dynamic.nil())
}
