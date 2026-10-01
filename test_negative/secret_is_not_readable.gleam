// expect: Unknown record field
import warden/config

pub fn main(secret: config.Secret) -> String {
  secret.reveal()
}
