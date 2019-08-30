#!/bin/bash
set -euxo pipefail
install -o root -g root -m 700 zcheck /usr/local/sbin/zcheck
install -o root -g root -m 755 zcheck.cron /etc/cron.weekly/zcheck
