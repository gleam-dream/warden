import gleeunit
import gleeunit/should
import warden

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn version_test() {
  warden.version()
  |> should.equal("0.1.0")
}
