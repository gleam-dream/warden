// expect: Type mismatch
import warden

pub fn main(client: warden.Client, session: warden.Session) {
  warden.recover_custody(client, session)
}
