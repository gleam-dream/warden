// expect: Unknown record field
import warden/config

pub fn main(key: config.SealingKey) -> BitArray {
  key.reveal()
}
