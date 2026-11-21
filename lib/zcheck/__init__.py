"""zcheck: filesystem integrity inventory and comparison.

Modules:
  common   schema, text helpers, config-file parsing
  dpkg     ownership, checksums and versions from dpkg's database
  scan     the filesystem walk and the `zcheck` command
  compare  classification, diff, audit and the `zcheck-diff` command
"""

__version__ = "1.1.0"
