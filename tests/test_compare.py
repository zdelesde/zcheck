import io
import os
import types
import unittest

from helpers import TreeCase, write
from zcheck.compare import (Classifier, audit, audit_command, diff, diff_command, field_changes,
                            open_runs, owner_line)
from zcheck.common import Output
from zcheck.config import Config


class FakeSyslog:
    """Stands in for the syslog module: records (level name, line)."""
    def __init__(self):
        self.lines = []

    def syslog(self, prio, msg):
        self.lines.append((prio, msg))


def syslog_output():
    out = Output()
    out.syslog = FakeSyslog()
    out._prio = {"info": "info", "notice": "notice", "warning": "warning", "err": "err"}
    return out


def entry(**kw):
    e = dict(type="F", mode=0o644, uid=0, gid=0, size=1, sha256="a" * 64, target=None,
             rdev=None, fstype=None, md5_status=None, conffile=0, path_text="/x")
    e.update(kw)
    return e


class Classify(unittest.TestCase):
    def cls(self, rules=(), old=None, new=None):
        default = {"pkga": "1", "pkgb": "1"}
        return Classifier(list(rules), default if old is None else old, default if new is None else new)

    def test_setuid_added(self):
        k, why, rule = self.cls().classify("/usr/bin/x", entry(), entry(mode=0o4755), ["pkga"], ["pkga"])
        self.assertEqual((k, rule), ("alarm", None))
        self.assertIn("setuid", why)
        k, _, _ = self.cls().classify("/usr/bin/x", None, entry(mode=0o2755), [], [])
        self.assertEqual(k, "alarm")

    def test_existing_setuid_is_not_an_addition(self):
        cls = self.cls(old={"pkga": "1"}, new={"pkga": "2"})
        k, _, _ = cls.classify("/usr/bin/su", entry(mode=0o4755), entry(mode=0o4755, sha256="b" * 64),
                               ["pkga"], ["pkga"])
        self.assertEqual(k, "explained")

    def test_checksum_mismatch_beats_package_upgrade(self):
        cls = self.cls(old={"pkga": "1"}, new={"pkga": "2"})
        k, _, _ = cls.classify("/usr/bin/x", entry(), entry(md5_status="modified"), ["pkga"], ["pkga"])
        self.assertEqual(k, "alarm")

    def test_package_upgrade_explains(self):
        cls = self.cls(old={"pkga": "1"}, new={"pkga": "2"})
        k, why, _ = cls.classify("/usr/bin/x", entry(), entry(sha256="b" * 64, md5_status="ok"),
                                 ["pkga"], ["pkga"])
        self.assertEqual(k, "explained")
        self.assertIn("pkga 1->2", why)

    def test_package_removal_explains_removed_files(self):
        cls = self.cls(old={"pkga": "1"}, new={})
        self.assertEqual(cls.classify("/usr/bin/x", entry(), None, ["pkga"], [])[0], "explained")

    def test_owned_but_unchanged_package(self):
        k, why, _ = self.cls().classify("/usr/bin/x", entry(), entry(sha256="b" * 64), ["pkga"], ["pkga"])
        self.assertEqual(k, "alarm")
        self.assertIn("didn't change", why)

    def test_unowned(self):
        self.assertEqual(self.cls().classify("/usr/local/bin/x", None, entry(), [], [])[0], "alarm")

    def test_device_node_outside_dev(self):
        k, _, _ = self.cls().classify("/usr/bin/x", None, entry(type="C", rdev="1:3"), [], [])
        self.assertEqual(k, "alarm")

    def test_conffiles_are_notices(self):
        k, _, _ = self.cls().classify("/etc/a.conf", entry(conffile=1, md5_status="ok"),
                                      entry(conffile=1, md5_status="modified"), ["pkga"], ["pkga"])
        self.assertEqual(k, "notice")

    def test_alternatives(self):
        old, new = entry(type="L", target=b"/a"), entry(type="L", target=b"/b")
        self.assertEqual(self.cls().classify("/usr/bin/ed", old, new, ["(alternatives:ed)"],
                                             ["(alternatives:ed)"])[0], "notice")
        cls = self.cls(old={"pkga": "1"}, new={"pkga": "2"})
        self.assertEqual(cls.classify("/usr/bin/ed", old, new, ["(alternatives:ed)"],
                                      ["(alternatives:ed)"])[0], "explained")

    def test_generated_default_rule(self):
        pyc = "/usr/lib/python3/dist-packages/m/__pycache__/m.pyc"
        k, _, rule = self.cls().classify(pyc, None, entry(), [], [])
        self.assertEqual(k, "alarm")                 # no package changed
        self.assertIn("(default)", rule)
        cls = self.cls(old={"pkga": "1"}, new={"pkga": "2"})
        self.assertEqual(cls.classify(pyc, None, entry(), [], [])[0], "explained")

    def test_etc_default_notice(self):
        self.assertEqual(self.cls().classify("/etc/hostname", entry(), entry(sha256="b" * 64), [], [])[0],
                         "notice")

    def test_config_rules_come_first(self):
        cls = self.cls(rules=[("ignore", "/opt"), ("notice", "/opt/*"), ("alarm", "/etc/sudoers")])
        self.assertEqual(cls.classify("/opt", None, entry(type="D"), [], [])[0], "ignore")
        k, _, rule = cls.classify("/opt/app/bin", None, entry(mode=0o4755), [], [])
        self.assertEqual((k, rule), ("notice", "notice /opt/* (config)"))
        self.assertEqual(cls.classify("/etc/sudoers", entry(conffile=1), entry(conffile=1, sha256="b"),
                                      ["sudo"], ["sudo"])[0], "alarm")


class Formatting(unittest.TestCase):
    def test_field_changes(self):
        o = entry(md5_status="ok", type="L", target=b"/a")
        n = entry(mode=0o4755, uid=1000, md5_status="modified", type="L", target=b"/b", sha256="b" * 64)
        self.assertEqual(field_changes(o, n), ["mode", "uid", "content", "target", "package checksum"])
        self.assertEqual(field_changes(entry(sha256=None, size=1), entry(sha256=None, size=9)), ["size"])

    def test_describe(self):
        from zcheck.compare import describe
        sha = "3f2a91c0" + "0" * 52 + "7b1e"
        self.assertEqual(describe(entry(mode=0o755, sha256=sha, md5_status="ok")),
                         "F 0755 0:0 sha256 3f2a91c0…7b1e, matches package")
        self.assertEqual(describe(entry(sha256=sha, md5_status="modified")),
                         "F 0644 0:0 sha256 3f2a91c0…7b1e, differs from package")
        self.assertEqual(describe(entry(sha256=sha, conffile=1, md5_status="modified")),
                         "F 0644 0:0 sha256 3f2a91c0…7b1e, conffile modified")
        self.assertEqual(describe(entry(sha256=None, size=42)), "F 0644 0:0 42 bytes (not hashed)")
        self.assertEqual(describe(entry(type="L", mode=0o777, target=b"/b")), "L 0777 0:0 -> /b")
        self.assertEqual(describe(entry(type="M", fstype="tmpfs")), "M 0644 0:0 tmpfs (not scanned)")

    def test_owner_line(self):
        old, new = {"a": "1", "b": "1", "c": "1"}, {"a": "2", "b": "1", "d": "1"}
        self.assertEqual(owner_line(["a"], old, new), "a 1 -> 2")
        self.assertEqual(owner_line(["c"], old, new), "c 1 (removed)")
        self.assertEqual(owner_line(["d"], old, new), "d 1 (newly installed)")
        self.assertEqual(owner_line([], old, new), "none")
        self.assertEqual(owner_line(["e"], old, new), "e (not installed)")
        self.assertEqual(owner_line(["a", "b", "c", "d"], old, new),
                         "a 1 -> 2, b 1, c 1 (removed), +1 more")


class EndToEnd(TreeCase):
    """Two real scans of a tree with package upgrades and tampering in between."""

    def setUp(self):
        super().setUp()
        for f in ("usr/bin/tool", "usr/bin/other", "usr/bin/mine"):
            write(self.t(f), f)
        write(self.t("etc/app.conf"), "conf")
        self.fake.add("pkga", "1.0", files=[self.t("usr/bin/tool")], md5=[self.t("usr/bin/tool")],
                      conffiles=[self.t("etc/app.conf")])
        self.fake.add("pkgb", "1.0", files=[self.t("usr/bin/other")], md5=[self.t("usr/bin/other")])
        self.old = self.scan()

        write(self.t("usr/bin/tool"), "tool v2")                      # upgrade
        self.fake.add("pkga", "2.0", files=[self.t("usr/bin/tool")], md5=[self.t("usr/bin/tool")],
                      conffiles=[self.t("etc/app.conf")])
        self.fake.write()
        write(self.t("usr/bin/other"), "tampered")                    # tamper, pkgb unchanged
        os.chmod(self.t("usr/bin/mine"), 0o4755)                      # setuid on unowned
        write(self.t("usr/bin/dropped"), "new")                       # new unowned
        write(self.t("etc/app.conf"), "edited")                       # edit conffile
        write(self.t("usr/lib/py/__pycache__/m.pyc"), "pyc")          # generated
        self.new = self.scan()

    def classes(self, rules=()):
        db = open_runs(self.new, self.old)
        from zcheck.compare import packages
        cls = Classifier(list(rules), packages(db, "o"), packages(db, "main"))
        return {c["path"][len(self.tree):]: c for c in diff(db, cls)}

    def test_diff_classes(self):
        c = self.classes()
        expect = {
            "/usr/bin/tool": "explained", "/usr/bin/other": "alarm", "/usr/bin/mine": "alarm",
            "/usr/bin/dropped": "alarm", "/etc/app.conf": "notice",
            "/usr/lib/py/__pycache__/m.pyc": "explained",
        }
        for path, klass in expect.items():
            with self.subTest(path=path):
                self.assertEqual(c[path]["class"], klass)
        self.assertEqual(c["/usr/bin/tool"]["owner"], "pkga 1.0 -> 2.0")
        other = c["/usr/bin/other"]
        self.assertEqual(other["detail"], "content, package checksum")
        self.assertRegex(other["was"], r"^F 0644 0:0 sha256 \S+, matches package$")
        self.assertRegex(other["now"], r"^F 0644 0:0 sha256 \S+, differs from package$")
        self.assertNotEqual(other["was"], other["now"])

    def test_diff_command_exit_and_output(self):
        args = types.SimpleNamespace(runs=[self.old, self.new], dir=None, all=False, json=False,
                                     strict=False, allow_host_mismatch=False)
        out = io.StringIO()
        self.assertEqual(diff_command(Config(), args, Output(out)), 1)
        text = out.getvalue()
        self.assertIn("PACKAGES (1)\n  pkga 1.0->2.0", text)
        self.assertIn("EXPLAINED (", text)
        self.assertNotIn("__pycache__", text)                 # explained items hidden without --all

    def test_no_changes_exits_zero(self):
        args = types.SimpleNamespace(runs=[self.new, self.new], dir=None, all=False, json=False,
                                     strict=False, allow_host_mismatch=False)
        out = io.StringIO()
        self.assertEqual(diff_command(Config(), args, Output(out)), 0)
        self.assertIn("zcheck diff: 0 alarm, 0 notice, 0 explained", out.getvalue())

    def test_audit(self):
        db = open_runs(self.new)
        found = {f["path"][len(self.tree):]: f["class"] for f in audit(db, [], False)["findings"]}
        self.assertEqual(found, {"/usr/bin/other": "alarm", "/usr/bin/mine": "alarm",
                                 "/etc/app.conf": "notice"})
        found = {f["path"][len(self.tree):] for f in audit(db, [], True)["findings"]}
        self.assertIn("/usr/bin/dropped", found)               # only with --unowned
        self.assertNotIn("/usr/lib/py/__pycache__/m.pyc", found)   # generated is skipped

    def test_audit_applies_rules(self):
        db = open_runs(self.new)
        rules = [("ignore", "*/other"), ("notice", "*/mine"), ("alarm", "*/app.conf")]
        found = {f["path"][len(self.tree):]: (f["class"], f["rule"]) for f in audit(db, rules, False)["findings"]}
        self.assertNotIn("/usr/bin/other", found)
        self.assertEqual(found["/usr/bin/mine"][0], "notice")
        self.assertEqual(found["/etc/app.conf"], ("alarm", "alarm */app.conf (config)"))

    def test_audit_command_json(self):
        import json
        args = types.SimpleNamespace(run=self.new, dir=None, unowned=False, json=True, strict=False)
        out = io.StringIO()
        self.assertEqual(audit_command(Config(), args, Output(out)), 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data["run"]["host"], "testhost")
        self.assertNotIn("setuid", data)

    def test_diff_to_syslog_is_one_line_per_item(self):
        args = types.SimpleNamespace(runs=[self.old, self.new], dir=None, all=False, json=False,
                                     strict=False, allow_host_mismatch=False)
        out = syslog_output()
        self.assertEqual(diff_command(Config(), args, out), 1)
        lines = out.syslog.lines
        other = [ln for ln in lines if ln[1].startswith("ALARM ~ changed ") and "/usr/bin/other | changed: "
                 "content, package checksum | was: F 0644 0:0 sha256 " in ln[1]
                 and ln[1].endswith(", differs from package | owner: pkgb 1.0")]
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0][0], "warning")
        self.assertTrue(any(p == "notice" and m.startswith("NOTICE ~ changed ") for p, m in lines))
        new = [m for _, m in lines if m.startswith("ALARM + new ") and "/usr/bin/dropped |" in m]
        self.assertEqual(len(new), 1)
        self.assertIn("| was: (not present) | now: F 0644 0:0 sha256 ", new[0])
        self.assertFalse(any("__pycache__" in m for _, m in lines))       # explained hidden
        self.assertIn(("warning", "zcheck diff: 5 alarm, 1 notice, 3 explained"), lines)
        self.assertFalse(any(m.strip() == "" for _, m in lines))


if __name__ == "__main__":
    unittest.main()


class AuditSetuid(TreeCase):
    """Setuid/setgid files in an audit: only problems are listed."""

    def setUp(self):
        super().setUp()
        for name in ("ok", "modified", "unverified", "unpackaged"):
            write(self.t("usr/bin", name), name, 0o4755)
        self.fake.add("pkg", files=[self.t("usr/bin", n) for n in ("ok", "modified", "unverified")],
                      md5=[self.t("usr/bin/ok"), self.t("usr/bin/modified")])
        write(self.t("usr/bin/modified"), "tampered", 0o4755)
        db = open_runs(self.scan())
        self.found = {f["path"][len(self.tree):]: f for f in audit(db, [], False)["findings"]}

    def test_unmodified_package_setuid_not_listed(self):
        self.assertNotIn("/usr/bin/ok", self.found)

    def test_modified_package_setuid_is_alarm(self):
        f = self.found["/usr/bin/modified"]
        self.assertEqual(f["class"], "alarm")
        self.assertIn("setuid/setgid file whose content doesn't match pkg", f["reason"])

    def test_unpackaged_setuid_is_alarm(self):
        self.assertEqual(self.found["/usr/bin/unpackaged"]["class"], "alarm")
        self.assertEqual(self.found["/usr/bin/unpackaged"]["owner"], "none")

    def test_unverifiable_package_setuid_is_notice(self):
        f = self.found["/usr/bin/unverified"]
        self.assertEqual(f["class"], "notice")
        self.assertIn("no package checksum", f["reason"])


class RemovedPackages(TreeCase):
    """A versioned package replaced by a newer one, as with kernel modules. apt
    usually leaves the old one in dpkg's database as "deinstall ok
    config-files" (rc), same version, with its files gone."""

    def setUp(self):
        super().setUp()
        self.old_ko = self.t("usr/lib/modules/6.8.0-45/kernel/x.ko")
        self.new_ko = self.t("usr/lib/modules/6.8.0-47/kernel/x.ko")
        write(self.old_ko, "old module")
        self.fake.add("linux-modules-6.8.0-45", "6.8.0-45.45", files=[self.old_ko], md5=[self.old_ko])
        self.old = self.scan()

        os.unlink(self.old_ko)
        os.rmdir(os.path.dirname(self.old_ko))
        write(self.new_ko, "new module")

    def changes(self):
        db = open_runs(self.new, self.old)
        from zcheck.compare import config_files_only, packages
        cls = Classifier([], packages(db, "o"), packages(db, "main"), config_files_only(db, "main"))
        return cls, {c["path"][len(self.tree):]: c for c in diff(db, cls)}

    def check(self):
        cls, c = self.changes()
        removed = c["/usr/lib/modules/6.8.0-45/kernel/x.ko"]
        self.assertEqual((removed["kind"], removed["class"]), ("removed", "explained"), removed)
        self.assertIn("linux-modules-6.8.0-45 removed", removed["reason"])
        added = c["/usr/lib/modules/6.8.0-47/kernel/x.ko"]
        self.assertEqual(added["class"], "explained", added)
        self.assertFalse([p for p, x in c.items() if x["class"] == "alarm"], c)
        return cls

    def test_left_in_config_files_state(self):
        self.fake.add("linux-modules-6.8.0-45", "6.8.0-45.45", status="deinstall ok config-files")
        self.fake.add("linux-modules-6.8.0-47", "6.8.0-47.47", files=[self.new_ko], md5=[self.new_ko])
        self.new = self.scan()
        cls = self.check()
        self.assertIn("linux-modules-6.8.0-45 removed (config files remain)",
                      [cls.pkg_change(p) for p in sorted(cls.changed)])

    def test_deleted_files_hidden_without_all(self):
        self.fake.add("linux-modules-6.8.0-45", "6.8.0-45.45", status="deinstall ok config-files")
        self.fake.add("linux-modules-6.8.0-47", "6.8.0-47.47", files=[self.new_ko], md5=[self.new_ko])
        self.new = self.scan()
        args = types.SimpleNamespace(runs=[self.old, self.new], dir=None, all=False, json=False,
                                     strict=False, allow_host_mismatch=False)
        out = io.StringIO()
        self.assertEqual(diff_command(Config(), args, Output(out)), 0)
        text = out.getvalue()
        self.assertNotIn("6.8.0-45/kernel", text)            # deletions are explained, so hidden
        self.assertIn("linux-modules-6.8.0-45 removed (config files remain)", text)
        out = io.StringIO()
        diff_command(Config(), types.SimpleNamespace(**{**vars(args), "all": True}), Output(out))
        self.assertIn("  - deleted  " + self.old_ko + "\n      was:      F 0644 0:0 sha256 ", out.getvalue())
        self.assertIn("\n      now:      (not present)\n", out.getvalue())

    def test_purged(self):
        del self.fake.packages["linux-modules-6.8.0-45"]
        self.fake.add("linux-modules-6.8.0-47", "6.8.0-47.47", files=[self.new_ko], md5=[self.new_ko])
        self.new = self.scan()
        self.check()
