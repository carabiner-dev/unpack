# RPM decomposer test fixtures

## `rhel8-libuuid/`

A minimal "system" root with a single installed package, used to exercise the
full `ExtractFromFS` path:

- `var/lib/rpm/Packages` — a BerkeleyDB-format RPM database containing one
  package, `libuuid-2.32.1-42.el8_8.x86_64`. Copied verbatim from
  [knqyf263/go-rpmdb](https://github.com/knqyf263/go-rpmdb) (Apache-2.0),
  which extracted it from a Red Hat Enterprise Linux 8.8 image.
- `etc/os-release` — a representative RHEL 8.8 os-release file, hand-written
  so the decomposer can derive the `pkg:rpm/rhel/...` namespace and the
  `distro=rhel-8.8` qualifier.
