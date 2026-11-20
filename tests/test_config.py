import os
import tempfile
import unittest

import helpers  # noqa: F401  (sets up the import path)
from zcheck.common import ZcheckError, ptext, read_directives, unescape_octal
from zcheck.config import Config


class ConfigFile(unittest.TestCase):
    def conf(self, text):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_missing_file_gives_defaults(self):
        cfg = Config.load("/nonexistent/zcheck.conf")
        self.assertIn(b"/var", cfg.exclude)
        self.assertIn("ext4", cfg.fstypes)
        self.assertTrue(cfg.owners and cfg.verify)
        self.assertEqual(cfg.rules, [])

    def test_scan_directives(self):
        cfg = Config.load(self.conf(
            "exclude /opt/data/   # trailing slash dropped\n"
            "unexclude /srv\n"
            "include /var/www/*/cgi-bin\n"
            "fstype nfs4\n"
            "owners off\n"
            "verify off\n"))
        self.assertIn(b"/opt/data", cfg.exclude)
        self.assertNotIn(b"/srv", cfg.exclude)
        self.assertIn("/var/www/*/cgi-bin", cfg.include)
        self.assertIn("nfs4", cfg.fstypes)
        self.assertFalse(cfg.owners)
        self.assertFalse(cfg.verify)

    def test_rules_keep_file_order(self):
        cfg = Config.load(self.conf("notice /opt/*\n\n# comment\nalarm /etc/sudoers\nignore /x\n"
                                    "generated /boot/*\n"))
        self.assertEqual(cfg.rules, [("notice", "/opt/*"), ("alarm", "/etc/sudoers"),
                                     ("ignore", "/x"), ("generated", "/boot/*")])

    def test_errors(self):
        for text, msg in (("bogus /x\n", "unknown directive"),
                          ("exclude\n", "needs an argument"),
                          ("owners maybe\n", "'on' or 'off'")):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ZcheckError, msg):
                    Config.load(self.conf(text))

    def test_error_reports_line_number(self):
        with self.assertRaisesRegex(ZcheckError, r":3: "):
            read_directives(self.conf("notice /a\n\nnope /b\n"), ("notice",))


class TextHelpers(unittest.TestCase):
    def test_ptext(self):
        self.assertEqual(ptext(b"/usr/bin/ls"), "/usr/bin/ls")
        self.assertEqual(ptext(b"/tmp/bad\xffname"), "/tmp/bad\\xffname")
        self.assertEqual(ptext(None), "-")

    def test_unescape_octal(self):
        self.assertEqual(unescape_octal(rb"/mnt/my\040disk"), b"/mnt/my disk")


if __name__ == "__main__":
    unittest.main()
