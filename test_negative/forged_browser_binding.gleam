// expect: Unknown module value
import warden

pub fn main() {
  warden.BrowserBinding("attacker-chosen")
}
