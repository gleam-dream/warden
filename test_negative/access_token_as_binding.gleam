// expect: Type mismatch
import warden

pub fn main(client: warden.Client, token: warden.AccessToken) {
  warden.complete_login(client, token)
}
