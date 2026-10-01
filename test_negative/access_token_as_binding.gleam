// expect: Type mismatch
import gleam/option.{Some}
import warden

pub fn main(client: warden.Client, token: warden.AccessToken) {
  warden.complete_login(client, warden.QueryCallback("x"), Some(token))
}
