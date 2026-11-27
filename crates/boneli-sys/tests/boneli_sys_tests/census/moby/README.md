# Docker's default seccomp profile, vendored

`default.json` is `seccomp/default.json` of
[moby/profiles](https://github.com/moby/profiles) at commit
`9ee3204f0d0cfa19ca2c6a7b0fcf5a2b353954ae` (2026-11-10), byte for byte:
18,182 bytes, SHA-256
`3320527d4568265ac97a077609b1bfd4cfd0d789eeb9239b7e094b1526675406`.
`LICENSE` is the repository's license at the same commit (Apache-2.0).

It is test data for the Docker comparison of ADR-007 D2:
`census/docker.rs` reads it with `boneli-json` and derives the lists
`docker-denied-x86_64.txt` and `docker-denied-aarch64.txt`, and
`docker_profile_bytes_pinned` fails if one byte changes. A new pin
replaces both files, updates the commit and hash here and in the list
headers, and re-derives the lists and the ADR's table.
