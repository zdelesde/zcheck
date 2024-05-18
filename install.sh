#!/bin/bash
set -euxo pipefail
mkdir -p /var/lib/zcheck /var/lib/packages
install -o root -g root -m 700 zcheck.py /usr/local/sbin/zcheck
install -o root -g root -m 755 zcheck.cron /etc/cron.weekly/zcheck
install -o root -g root -m 755 packages.cron /etc/cron.weekly/packages
