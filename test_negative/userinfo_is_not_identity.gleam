// expect: Type mismatch
import warden

pub fn main(info: warden.UserInfo) -> String {
  warden.subject(info)
}
