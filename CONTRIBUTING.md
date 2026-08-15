# Contributing

Development of this project happens upstream; this repository publishes
each release as a tagged snapshot.

## What this means

- **Pull requests cannot be merged here.** The contents are replaced
  wholesale at every release, so a PR opened against this repository has
  nothing durable to land on. PRs are closed automatically with a link to
  this page.
- **Issues are very welcome.** Bug reports, feature requests, and questions
  filed here are read and triaged. Please include the crate version
  (`Cargo.toml` `[package].version`) and a minimal reproduction.
- **Security reports:** please email **security@mcpg.dev** rather than
  opening a public issue.

## Versions

The version in `Cargo.toml` is authoritative, and git tags here are
`v{version}` — this crate is consumed by git reference, not via crates.io:

```toml
[dependencies]
# take the tag from the latest release of this repository
<this-crate> = { git = "<this-repository-url>", tag = "v<version>" }
```

Each tagged commit is a complete snapshot of the crate at that release.
Dependency updates arrive with the next release; this repository runs no
Dependabot/Renovate.

Thanks for using MCPG.
