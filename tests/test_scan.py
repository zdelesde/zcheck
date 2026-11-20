import hashlib
import os
import sqlite3
import unittest

from helpers import TreeCase, write
from zcheck.config import Config
from zcheck.scan import excluded_ancestor, read_mounts, scan_roots


class Scan(TreeCase):
    def entries(self, run):
        db = sqlite3.connect(run)
        db.row_factory = sqlite3.Row
        self.addCleanup(db.close)
        return {r["path_text"][len(self.tree):] or "/": dict(r) for r in db.execute("SELECT * FROM entry")}, db

    def test_entry_types_and_metadata(self):
        write(self.t("file"), b"hello", 0o4755)
        os.symlink("file", self.t("link"))
        os.mkfifo(self.t("fifo"))
        os.mkdir(self.t("dir"))
        e, db = self.entries(self.scan())
        self.assertEqual(e["/file"]["type"], "F")
        self.assertEqual(e["/file"]["mode"], 0o4755)
        self.assertEqual(e["/file"]["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(e["/link"]["type"], "L")
        self.assertEqual(e["/link"]["target"], b"file")
        self.assertEqual(e["/fifo"]["type"], "P")
        self.assertEqual(e["/dir"]["type"], "D")
        run = db.execute("SELECT * FROM run").fetchone()
        self.assertEqual((run["entries"], run["errors"]), (len(e), 0))
        self.assertIsNotNone(run["finished"])

    @unittest.skipUnless(os.geteuid() == 0, "mknod needs root")
    def test_device_node(self):
        os.mknod(self.t("null"), 0o20644, os.makedev(1, 3))
        e, _ = self.entries(self.scan())
        self.assertEqual((e["/null"]["type"], e["/null"]["rdev"]), ("C", "1:3"))

    def test_non_utf8_names_are_exact(self):
        name = os.fsencode(self.tree) + b"/bad\xffname\n\tx"
        with open(name, "wb") as f:
            f.write(b"x")
        _, db = self.entries(self.scan())
        row = db.execute("SELECT path, path_text FROM entry WHERE path = ?", (name,)).fetchone()
        self.assertEqual(row["path"], name)
        self.assertTrue(row["path_text"].endswith("bad\\xffname\n\tx"))

    def test_excludes(self):
        write(self.t("skip/inner"), "x")
        write(self.t("swap"), "data")
        cfg = Config()
        cfg.exclude = {os.fsencode(self.t("skip")), os.fsencode(self.t("swap"))}
        e, _ = self.entries(self.scan(cfg))
        self.assertEqual(e["/skip"]["type"], "D")        # recorded...
        self.assertNotIn("/skip/inner", e)               # ...but not descended
        self.assertIsNone(e["/swap"]["sha256"])          # excluded file: metadata only

    def test_unscanned_filesystem_is_an_M_entry(self):
        write(self.t("inner"), "x")
        self.fake.write()
        from zcheck.scan import write_run
        run = os.path.join(self.tmp, "m.db")
        write_run(Config(), [os.fsencode(self.tree)], run, self.fake.load(), "h",
                  mounts={b"/": "ext4", os.fsencode(self.tree): "tmpfs"}, swapfiles=set())
        e, _ = self.entries(run)
        self.assertEqual((e["/"]["type"], e["/"]["fstype"]), ("M", "tmpfs"))
        self.assertNotIn("/inner", e)

    def test_package_checksum_status(self):
        write(self.t("good"), "v1")
        write(self.t("bad"), "v1")
        write(self.t("app.conf"), "c")
        self.fake.add("pkg", files=[self.t("good"), self.t("bad")],
                      md5=[self.t("good"), self.t("bad")], conffiles=[self.t("app.conf")])
        self.fake.write()
        write(self.t("bad"), "tampered")
        write(self.t("app.conf"), "edited")
        e, db = self.entries(self.scan())
        self.assertEqual(e["/good"]["md5_status"], "ok")
        self.assertEqual(e["/bad"]["md5_status"], "modified")
        self.assertEqual((e["/app.conf"]["md5_status"], e["/app.conf"]["conffile"]), ("modified", 1))
        owners = db.execute("SELECT p.name, p.version FROM owner o JOIN package p ON p.id = o.package_id "
                            "WHERE o.path = ?", (os.fsencode(self.t("good")),)).fetchall()
        self.assertEqual([tuple(r) for r in owners], [("pkg", "1.0")])

    def test_vanished_entries_are_counted_not_errors(self):
        self.fake.write()
        from zcheck.scan import Scanner
        db = sqlite3.connect(":memory:")
        from zcheck.common import SCHEMA
        db.executescript(SCHEMA)
        s = Scanner(Config(), self.fake.load(), db, mounts={b"/": "ext4"}, swapfiles=set())
        s.entry(os.fsencode(self.t("gone")), None, None, [])
        self.assertEqual((s.vanished, s.errors), (1, 0))


class Helpers(TreeCase):
    def test_excluded_ancestor(self):
        ex = {b"/home"}
        self.assertTrue(excluded_ancestor(b"/home/zac/.ssh", ex))
        self.assertFalse(excluded_ancestor(b"/etc/ssh", ex))

    def test_scan_roots_adds_includes_under_excludes_only(self):
        os.makedirs(self.t("home/zac/.ssh"))
        os.makedirs(self.t("etc/ssh"))
        cfg = Config()
        cfg.exclude = {os.fsencode(self.t("home"))}
        cfg.include = [self.t("home/*/.ssh"), self.t("etc/ssh"), self.t("missing/*")]
        self.assertEqual(scan_roots(cfg), [b"/", os.fsencode(self.t("home/zac/.ssh"))])
        self.assertEqual(scan_roots(cfg, ["/usr/bin/"]), [b"/usr/bin"])

    def test_read_mounts(self):
        path = os.path.join(self.tmp, "mounts")
        with open(path, "w") as f:
            f.write("/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n"
                    "/dev/sdb1 /mnt/my\\040disk xfs rw 0 0\n")
        self.assertEqual(read_mounts(path), {b"/": "ext4", b"/proc": "proc", b"/mnt/my disk": "xfs"})


if __name__ == "__main__":
    unittest.main()
