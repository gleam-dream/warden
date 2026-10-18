# The deprecated-catch compiler option applies only to the frozen JOSE oracle build

<a id="adr-0016"></a>

- **Decision:** the root build runs `gleam build --warnings-as-errors` with `ERL_COMPILER_OPTIONS='[nowarn_deprecated_catch]'` set for that command alone. Authored Erlang compiles with `erlc -Werror` and no option, and the tests run without it.
- **Need:** the exact test-only erlang-jose 1.11.12 oracle uses unary `catch`, which OTP 29 deprecates. Its warnings-as-errors build fails without the option, while the pin and upstream source must stay unchanged to remain a valid oracle.
- **Alternatives:** exporting the option in the shell hides deprecated `catch` in authored Erlang. Patching or forking the oracle invalidates its role as an independent pin. Dropping warnings-as-errors weakens the gate for all Gleam code.
- **Consequences:** `scripts/check`, `scripts/provider-check` and `scripts/benchmark` apply the scoped build themselves. Separate consumers do not depend on the oracle and need no option. A fresh manual root build repeats the same three steps: scoped build, `scripts/erlang-check`, `WARDEN_SUITE=fast gleam test`.
- **Evidence limits:** the option excuses one known deprecation in one frozen test-only dependency. It makes no claim about the oracle's behavior on later OTP releases.
