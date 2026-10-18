# The design's defaults table is the single owner of public limits and setters

<a id="adr-0018"></a>

- **Decision:** the "Public defaults and setters" table in `docs/design/design.typ` states every public default, bound and the setter that overrides it. The README, `AGENTS.md` and consumer-facing text link to it and restate no default values.
- **Need:** defaults were repeated in a usage guide, the README and the application guide. Three copies of roughly forty values drift, and a reader cannot tell which copy is authoritative.
- **Alternatives:** a generated table from `config.gleam` would not carry the non-configurable bounds, the cleanup semantics or the HTTP Gun inner limits. Keeping defaults only in doc comments scatters them across modules.
- **Consequences:** a change to a default or setter changes one design table in the same change. Defaults with a setter are overridden only through that setter, and no default is read from the environment. Non-configurable bounds appear in the same table with no setter.
- **Evidence limits:** the table is verified by review and by the configuration tests that assert individual values. No gate compares the table with the code.
