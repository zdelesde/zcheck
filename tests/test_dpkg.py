import os
import unittest

from helpers import TreeCase, md5_of, write
from zcheck.dpkg import Dpkg


class DpkgDatabase(TreeCase):
    def setUp(self):
        super().setUp()
        write(self.t("usr/bin/tool"), "tool")
        write(self.t("usr/bin/other"), "other")
        write(self.t("etc/app.conf"), "conf")
        write(self.t("usr/lib/libx.so"), "lib")

    def test_ownership_and_versions(self):
        self.fake.add("pkga", "2.1", files=[self.t("usr/bin/tool")]).write()
        d = self.fake.load()
        self.assertEqual(d.owner_names(os.fsencode(self.t("usr/bin/tool"))), ["pkga"])
        self.assertEqual(d.owner_names(os.fsencode(self.t("usr/bin"))), ["pkga"])
        self.assertEqual(d.versions["pkga"][0], "2.1")
        self.assertEqual(d.owner_names(os.fsencode(self.t("usr/bin/other"))), [])

    def test_multiarch_names_match_info_files(self):
        self.fake.add("libx", files=[self.t("usr/lib/libx.so")], multiarch_same=True).write()
        d = self.fake.load()
        self.assertEqual(d.owner_names(os.fsencode(self.t("usr/lib/libx.so"))), ["libx:amd64"])
        self.assertIn("libx:amd64", d.versions)
        self.assertEqual(d.ids["libx"], d.ids["libx:amd64"])

    def test_package_checksums(self):
        self.fake.add("pkga", files=[self.t("usr/bin/tool")], md5=[self.t("usr/bin/tool")]).write()
        sums, conffile = self.fake.load().expected_md5(os.fsencode(self.t("usr/bin/tool")))
        self.assertEqual(sums, {md5_of(self.t("usr/bin/tool"))})
        self.assertFalse(conffile)

    def test_conffiles(self):
        self.fake.add("pkga", conffiles=[self.t("etc/app.conf")]).write()
        sums, conffile = self.fake.load().expected_md5(os.fsencode(self.t("etc/app.conf")))
        self.assertTrue(conffile)
        self.assertEqual(sums, {md5_of(self.t("etc/app.conf"))})

    def test_verify_off_still_flags_conffiles(self):
        self.fake.add("pkga", conffiles=[self.t("etc/app.conf")],
                      files=[self.t("usr/bin/tool")], md5=[self.t("usr/bin/tool")]).write()
        d = self.fake.load(verify=False)
        self.assertEqual(d.expected_md5(os.fsencode(self.t("etc/app.conf"))), (None, True))
        self.assertEqual(d.expected_md5(os.fsencode(self.t("usr/bin/tool"))), (None, False))

    def test_alternatives(self):
        link = self.t("usr/bin/editor")
        self.fake.alternative("editor", link).write()
        d = self.fake.load()
        self.assertEqual(d.owner_names(os.fsencode(link)), ["(alternatives:editor)"])
        self.assertEqual(d.owner_names(b"/etc/alternatives/editor"), ["(alternatives:editor)"])

    def test_package_diversion(self):
        frm, to = self.t("usr/bin/tool"), self.t("usr/bin/tool.distrib")
        write(to, "original")
        self.fake.add("pkga", files=[frm], md5=[frm])
        self.fake.add("diverter", files=[frm])
        self.fake.divert(frm, to, "diverter").write()
        d = self.fake.load()
        self.assertEqual(d.owner_names(os.fsencode(frm)), ["diverter"])
        self.assertEqual(d.owner_names(os.fsencode(to)), ["pkga"])
        # The diverted-away copy is checked against pkga's checksum for the original path.
        sums, _ = d.expected_md5(os.fsencode(to))
        self.assertEqual(sums, {md5_of(frm)})

    def test_local_diversion(self):
        frm, to = self.t("usr/bin/tool"), self.t("usr/bin/tool.real")
        self.fake.add("pkga", files=[frm]).divert(frm, to, ":").write()
        d = self.fake.load()
        self.assertEqual(d.owner_names(os.fsencode(frm)), ["(local-diversion)"])
        self.assertEqual(d.owner_names(os.fsencode(to)), ["pkga"])

    def test_usrmerge_spellings(self):
        self.fake.add("coreutils", files=["/bin/ls"]).write()
        d = Dpkg(self.fake.admindir, usrmerged={b"/bin": b"/usr/bin"})
        d.load()
        self.assertEqual(d.owner_names(b"/usr/bin/ls"), ["coreutils"])
        self.assertEqual(d.owner_names(b"/bin/ls"), ["coreutils"])
        self.assertEqual(d.spellings(b"/binx/ls"), (b"/binx/ls",))

    def test_missing_admindir(self):
        d = Dpkg(os.path.join(self.tmp, "nope"), usrmerged={})
        self.assertFalse(d.load())
        self.assertFalse(d.loaded)


if __name__ == "__main__":
    unittest.main()
