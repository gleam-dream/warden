// expect: Unknown module value
import warden/config

pub fn main() {
  config.Config(issuer: "http://evil")
}
