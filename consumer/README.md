# warden reference consumer

A separate relying-party application that exercises Warden's public API against
the local test provider. It supplies browser routes, application session storage
and route protection, and holds one runnable example per usage topic.

| Topic                                          | Example                                               |
| ---------------------------------------------- | ----------------------------------------------------- |
| Sign in, call an API, sign out                 | `src/warden_reference/usage/login.gleam`              |
| Run under a supervisor                         | `src/warden_reference/usage/supervision.gleam`        |
| Durable sessions, conditional writes, nodes    | `src/warden_reference/usage/durable_store.gleam`      |
| Several callback addresses                     | `src/warden_reference/usage/callback_addresses.gleam` |
| Resource-server validation and introspection   | `src/warden_reference/usage/resource_server.gleam`    |
| Local test provider                            | `src/warden_reference/usage/test_provider.gleam`      |
| Application decisions around Warden's evidence | `src/warden_reference/usage/responsibilities.gleam`   |

`test/usage_test.gleam` runs every example. The README at the repository root shows
related usage snippets, whose consistency is reviewed manually. `src/warden_reference/web.gleam` holds the browser routes and
`protect.gleam` the route protection; `test/warden_reference_test.gleam` runs the
common login path and `browser/` holds the browser reproduction.

```sh
cd consumer && gleam test
```

The design's "Application responsibilities" section states the decisions this
application makes.
