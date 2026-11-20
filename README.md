# zcheck

Filesystem integrity inventory for Debian/Ubuntu hosts, checked against dpkg's
package metadata.

```
zcheck [scan]              record a run in /var/lib/zcheck/runs/, update latest.db
zcheck diff [OLD NEW]      compare two runs (default: previous vs latest)
zcheck audit [RUN]         check one run against package metadata
```

Settings and classification rules live in `/etc/zcheck.conf`; an annotated
example is in `/usr/share/zcheck/zcheck.conf.example`. See
`zcheck COMMAND --help` for options, output format and exit codes.

## Layout

```
bin/zcheck            entry point (python3 -I; LIBDIR filled in at install)
lib/zcheck/           common, config, dpkg, scan, compare, cli
tests/                unittest suite (make test)
examples/zcheck.conf  annotated config
packaging/control.in  Debian control template
```

## Building

```
make test                          # run the tests
make deb                           # build/zcheck_<version>_all.deb
make deb MAINTAINER="Zac <zac@wozzle.com>"
make install DESTDIR=/tmp/stage    # plain install, PREFIX=/usr by default
```

The package ships `DEBIAN/md5sums`, so once installed zcheck verifies its own
files like any other package (`dpkg --verify zcheck`, `zcheck audit`).
The version comes from `lib/zcheck/__init__.py`.
