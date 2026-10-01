// expect: Type mismatch
import warden

pub fn main(info: warden.TokenInfo) -> String {
  warden.subject(info)
}
