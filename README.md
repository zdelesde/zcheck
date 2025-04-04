# zcheck
A super-simple tripwire-like script

By default, zcheck will be run out of /etc/cron.weekly.  It will traverse the whole filesystem, excluding directories that are expected to have changing content, making a manifest of directories, files and links, including their ownership, permissions and sha256sum.  It is easy to compare different versions of the manifest to detect host changes, both intentional and unintentional or malicious.  It's also easy to compare the contents of different hosts.

```
root@animal:/var/lib/zcheck# diff 20201115-064708 20201122-064710
460c460
< /etc/aliases.db       F       0644    0       0       a9ed47b3294a6c23da821f40fe569ec49f3a6139
---
> /etc/aliases.db       F       0644    0       0       354e7118b7bd6cf157b710e7a6c7e9315aea4016
2036c2036
< /etc/postfix/main.cf  F       0644    0       0       0478d30743672f950bdf3e54d9f8e9fab432fb2e
---
> /etc/postfix/main.cf  F       0644    0       0       1c6ec759ea7b82c354e785a66b13dac723831643
2046c2046
< /etc/postfix/virtual.db       F       0644    0       0       c974eb1117142ddb589f200750629b59d25bcfdf
---
> /etc/postfix/virtual.db       F       0644    0       0       09b82bc8cb2bfef46abdbb9fb3eb862ffed71a4d
2661c2661
< /etc/ssl/certs/snakeoil.com.crt       F       0644    0       0       4c7c5c049c65e62f271fc74e99c0a5336b5c3bb2
---
> /etc/ssl/certs/snakeoil.com.crt       F       0644    0       0       07d681da4c1483f90def07bdb4aad490ab0d7846
2670c2670
< /etc/ssl/private/snakeoil.com.key     F       0640    0       122     c09b065a9204bdd71d619b22400f39ec2750650b
---
> /etc/ssl/private/snakeoil.com.key     F       0640    0       0       c09b065a9204bdd71d619b22400f39ec2750650b
```

Another script is included that makes a manifest of installed packages.
