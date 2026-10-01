//// Test entry point. See `warden_test_runner.erl` for suite selection.

pub fn main() -> Nil {
  run()
}

@external(erlang, "warden_test_runner", "main")
fn run() -> Nil
