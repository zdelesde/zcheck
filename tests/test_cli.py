"""The installed-style entry point, run as a subprocess."""

import os
import subprocess
import sys
import time

from helpers import ZCHECK, TreeCase, write


class CommandLine(TreeCase):
    def run_zcheck(self, *args):
        return subprocess.run([sys.executable, "-I", ZCHECK] + list(args),
                              capture_output=True, text=True)

    def scan_args(self):
        self.fake.write()
        return ["-c", os.path.join(self.tmp, "zcheck.conf"), "-d", os.path.join(self.tmp, "state"),
                "--root", self.tree, "--dpkg-admindir", self.fake.admindir]

    def test_bare_zcheck_scans_then_diff_and_audit(self):
        write(self.t("usr/bin/tool"), "v1")
        r = self.run_zcheck(*self.scan_args())
        self.assertEqual(r.returncode, 0, r.stderr)
        state = os.path.join(self.tmp, "state")
        self.assertTrue(os.path.islink(os.path.join(state, "latest.db")))

        r = self.run_zcheck("diff", "-d", state)
        self.assertEqual(r.returncode, 2)
        self.assertIn("need two runs", r.stderr)

        time.sleep(1.1)                       # run files are named by the second
        write(self.t("usr/bin/new"), "x")
        r = self.run_zcheck("scan", *self.scan_args())
        self.assertEqual(r.returncode, 0, r.stderr)

        r = self.run_zcheck("-d", state, "diff")             # option before the subcommand
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("/usr/bin/new", r.stdout)
        r = self.run_zcheck("audit", "-d", state)            # and after
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("zcheck audit: 0 alarm, 0 notice, 0 explained", r.stdout)

        r = self.run_zcheck("--syslog", "diff", "-d", state)  # results go to syslog, not stdout
        self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
        r = self.run_zcheck("scan", "--syslog", *self.scan_args())
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))

    def test_config_rules_affect_exit_code(self):
        write(self.t("a"), "x")
        args = self.scan_args()
        self.run_zcheck(*args)
        time.sleep(1.1)
        write(self.t("b"), "x")
        self.run_zcheck(*args)
        conf = os.path.join(self.tmp, "zcheck.conf")
        with open(conf, "w") as f:
            f.write("ignore */b\n")
        r = self.run_zcheck("diff", "-c", conf, "-d", os.path.join(self.tmp, "state"))
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_bad_config_exits_2(self):
        conf = os.path.join(self.tmp, "bad.conf")
        with open(conf, "w") as f:
            f.write("frobnicate yes\n")
        r = self.run_zcheck("audit", "-c", conf, "-d", self.tmp)
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown directive", r.stderr)

    def test_syslog_and_json_conflict(self):
        r = self.run_zcheck("diff", "--syslog", "--json", "-d", self.tmp)
        self.assertEqual(r.returncode, 2)
        self.assertIn("can't be combined", r.stderr)

    def test_errors_reach_stderr_with_syslog(self):
        r = self.run_zcheck("--syslog", "diff", "-d", self.tmp)
        self.assertEqual(r.returncode, 2)
        self.assertIn("runs: No such file or directory", r.stderr)

    def test_help_and_version(self):
        for args in (["--help"], ["scan", "--help"], ["diff", "--help"], ["audit", "--help"], ["--version"]):
            with self.subTest(args=args):
                r = self.run_zcheck(*args)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_no_bytecode_written(self):
        self.run_zcheck("--help")
        lib = os.path.join(os.path.dirname(ZCHECK), os.pardir, "lib", "zcheck")
        self.assertFalse(os.path.exists(os.path.join(lib, "__pycache__")))
