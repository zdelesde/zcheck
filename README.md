# zcheck
A super-simple tripwire-like script

By default, zcheck will be run out of /etc/cron.weekly.  It will traverse the whole filesystem, excluding directories that are expected to have changing content, making a manifest of directories, files and links, including their ownership, permissions and sha256sum.  It is easy to compare different versions of the manifest to detect host changes, both intentional and unintentional or malicious.  It's also easy to compare the contents of different hosts.

Another script is included that makes a manifest of installed packages.

Note: this script *assumes* that itself, the Digest::SHA perl module and any other dependencies have not been tampered with.
