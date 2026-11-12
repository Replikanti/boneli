# Boneli

Reproduce bugs and find root causes with evidence.

Boneli builds a replica of your application with data for every bug, reproduces the bug in it, finds the root cause with verified citations and opens the fix as a pull request. Agents run in an isolated sandbox with no network and no secrets, and every gate is deterministic: a fix only gets through when the reproduction test goes from red to green in a clean environment.

## Status

Early design. There is no code yet. Start with the [architecture proposal](docs/ARCHITECTURE.md).

## Principles

- **Pure Rust** with a minimal, allowlisted set of dependencies.
- **Hexagonal architecture:** an I/O-free domain, ports as traits, every adapter in its own crate.
- **Evidence over claims:** reproduction tests, citations verified against the analyzed commit, and fixes verified in a clean sandbox.
- **The runner is open source**, so you can read exactly what runs in your network.

## Name

The Boneli Reflex-Arc Test appears in Philip K. Dick's novel *Do Androids Dream of Electric Sheep?* as an alternative to the Voigt-Kampff test for telling androids from humans. Boneli does the same for fixes: it tells a real one from a fake.

Boneli is part of [Replikanti](https://github.com/Replikanti).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The license does not grant rights to the Boneli name or logo.
