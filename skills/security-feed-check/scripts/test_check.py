"""Run: python3 -B scripts/test_check.py  (stdlib only, no network; -B avoids writing __pycache__)."""
import contextlib, io, json, os, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check
from datetime import datetime, timedelta, timezone

INC = {"slug": "s1", "title": "Node.js HTTP smuggling", "product": "Node.js", "tags": ["node"], "status": "live",
       "severity": "high", "patchStatus": "patched", "updatedAt": "2026-11-01T00:00:00Z",
       "url": "https://pwn.watch/s1", "json": "https://pwn.watch/s1.json"}
RSS = """<rss><channel>
<item><title>A</title><link>https://x/a</link><guid>a@2026-11-05</guid><description>Patch.</description>
<category>Needs attention</category><category>SSH</category></item>
<item><title>B</title><link>https://x/b</link><guid>b@2026-07-20</guid><description>Old.</description>
<category>Reference</category></item>
</channel></rss>"""


def feeds(incidents, rss=RSS, updated=None):
    updated = updated or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pwn = json.dumps({"updatedAt": updated, "incidents": incidents}).encode()
    return lambda url: pwn if url == check.INCIDENTS_URL else rss.encode()


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        check.WATCHLIST, check.SEEN = os.path.join(self.dir, "watchlist.json"), os.path.join(self.dir, "seen.json")
        json.dump({"tags": ["ssh"], "keywords": ["node.js"]}, open(check.WATCHLIST, "w"))

    def run_check(self, fetch, commit=False):
        check.fetch_raw = fetch
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            check.check(all_live=True, commit=commit)
        return out.getvalue()

    def test_matching_is_whole_word_or_tag(self):
        watch = {"tags": {"ssh"}, "keywords": ["node"]}
        self.assertTrue(check.matches({"title": "node RCE"}, watch))
        self.assertFalse(check.matches({"title": "nodejs RCE"}, watch))
        self.assertTrue(check.matches({"title": "x", "tags": ["SSH"]}, watch))

    def test_zero_wire_keeps_only_needs_attention(self):
        check.fetch_raw = feeds([])
        items, total = check.zero_wire()
        self.assertEqual(total, 2)
        self.assertEqual([(z["slug"], z["guid"]) for z in items], [("zerowire:a", "a@2026-11-05")])

    def test_lock_versions(self):
        mix = '%{\n  "bandit": {:hex, :bandit, "1.14.1", "abc", [:mix], [], "hexpm", "def"},\n}'
        npm = json.dumps({"packages": {"": {}, "node_modules/vite": {"version": "6.0.1"},
                                       "node_modules/vite/node_modules/@s/x": {"version": "1"},
                                       "node_modules/y/node_modules/@s/x": {"version": "1"},
                                       "node_modules/@s/x": {"version": "2"}}})
        self.assertEqual(check.lock_versions(mix), "bandit 1.14.1")
        self.assertEqual(check.lock_versions(npm), "@s/x 1;@s/x 2;vite 6.0.1")  # nested copies kept, deduped
        # unreadable formats must say UNKNOWN, never print an empty (clean-looking) list
        self.assertTrue(check.lock_versions('vite@^6:\n  version "6.0.1"\n').startswith("UNKNOWN"))  # yarn.lock
        self.assertTrue(check.lock_versions('{"lockfileVersion": 1, "dependencies": {}}').startswith("UNKNOWN"))

    def test_commit_then_rerun_reports_nothing_new(self):
        first = self.run_check(feeds([INC]), commit=True)
        self.assertIn("1 new/updated", first)
        self.assertIn("🆕", first)
        second = self.run_check(feeds([INC]))
        self.assertIn("0 new/updated", second)
        self.assertNotIn("🆕", second)
        self.assertIn("Node.js HTTP smuggling", second)  # still listed under all live matches
        self.assertFalse(os.path.exists(check.SEEN + ".tmp"))

    def test_empty_feeds_fail_loudly(self):
        with self.assertRaises(SystemExit):
            self.run_check(feeds([]))
        with self.assertRaises(SystemExit):
            self.run_check(feeds([INC], rss="<rss><channel></channel></rss>"))

    def test_feed_failure_is_coverage_lost(self):
        def down(url):
            raise OSError("network down")
        with self.assertRaises(SystemExit) as cm:
            self.run_check(down)
        self.assertIn("COVERAGE LOST: pwn.watch", str(cm.exception.code))
        with self.assertRaises(SystemExit) as cm:
            self.run_check(feeds([INC], rss="<rss><unclosed>"))
        self.assertIn("COVERAGE LOST: Zero Wire", str(cm.exception.code))
        self.assertFalse(os.path.exists(check.SEEN))

    def test_unedited_example_watchlist_is_flagged(self):
        self.assertNotIn("EXAMPLE WATCHLIST", self.run_check(feeds([INC])))
        json.dump(json.load(open(check.EXAMPLE)), open(check.WATCHLIST, "w"))
        self.assertIn("EXAMPLE WATCHLIST", self.run_check(feeds([INC])))


    def test_stale_pwn_watch_feed_is_flagged(self):
        self.assertNotIn("STALE FEED", self.run_check(feeds([INC])))
        self.assertIn("STALE FEED: pwn.watch data is 48h old", self.run_check(feeds([INC], updated=(
            datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ"))))


class ProbeTest(unittest.TestCase):
    def test_run_reports_failures_as_unknown(self):
        self.assertEqual(check.run(["sh", "-c", "echo ok"]), "ok")
        self.assertTrue(check.run(["no-such-binary-xyz"]).startswith("UNKNOWN (not on PATH"))
        self.assertEqual(check.run(["sh", "-c", "echo oops >&2; exit 3"]), "UNKNOWN (exit 3: oops)")

    def test_system_packages_reads_whichever_package_db_exists(self):
        which, run = check.shutil.which, check.run
        try:
            check.shutil.which = lambda c: "/usr/bin/pacman" if c == "pacman" else None
            check.run = lambda argv: "openssl 3.5.1-1\nzlib 1.3-2"
            self.assertEqual(check.system_packages(), [("pacman", "openssl 3.5.1-1;zlib 1.3-2")])
            check.shutil.which = lambda c: None
            self.assertTrue(check.system_packages()[0][1].startswith("UNKNOWN"))
        finally:
            check.shutil.which, check.run = which, run

    def test_notify_passes_cleaned_text_as_an_argument(self):
        calls, run = [], check.run
        try:
            check.run = lambda argv: calls.append(argv) or ""
            with contextlib.redirect_stdout(io.StringIO()):
                check.notify('2 need you "; `x` $(y) ~', plat="darwin")
                check.notify("all clear", plat="linux")
        finally:
            check.run = run
        mac, linux = calls
        self.assertEqual(mac[0], "osascript")
        self.assertFalse(set(mac[-1]) & set('"`$;~'))  # text is the last argv item, stripped of shell/AppleScript chars
        self.assertTrue(mac[-1].startswith("2 need you"))
        self.assertTrue(all("need you" not in a for a in mac[:-1]))  # never spliced into the script itself
        self.assertEqual(linux, ["notify-send", "Security feed check", "all clear"])

    def test_git_show_separates_missing_file_from_git_failure(self):
        repo = tempfile.mkdtemp()
        git = lambda *a: subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True)
        git("init", "-q")
        open(os.path.join(repo, "mix.lock"), "w").write("x")
        git("add", "mix.lock")
        git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "x")
        self.assertEqual(check.git_show(repo, "HEAD", "mix.lock"), "x")
        self.assertIsNone(check.git_show(repo, "HEAD", "Dockerfile"))
        self.assertTrue(check.git_show(repo, "no-such-ref", "Dockerfile").startswith("UNKNOWN"))


if __name__ == "__main__":
    unittest.main()
