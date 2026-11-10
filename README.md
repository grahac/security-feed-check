# security-feed-check

Each morning, your AI coding agent (Claude Code or Codex) checks the day's new security vulnerabilities against the software actually installed on your Mac, and tells you only about the ones that affect you, each with the exact fix.

> **Beta.** This depends on two third-party feeds, pwn.watch and Cloudflare Radar Zero Wire, that this project does not control. If either feed stops updating or goes away, coverage drops; the check says so (`STALE FEED`, `COVERAGE LOST`) rather than reporting all clear. Treat it as an extra signal, not your only one.

## At a glance

| | |
|---|---|
| **What it is** | A skill (instructions plus a small Python script) for [Claude Code](https://claude.com/claude-code) or [Codex](https://github.com/openai/codex). Your agent runs it. There is no app, daemon or account. |
| **Runs on** | macOS with Python 3.9+ (included with the Xcode Command Line Tools). Linux partly; see below. |
| **Checks on your computer** | macOS version, apps in `/Applications`, Homebrew formulae and casks, global npm packages, Node, Python, Ruby, Elixir, Erlang, Docker and Git versions, and any lockfiles you list (`package-lock.json`, `mix.lock`). |
| **Checks on your servers** | Optional. "Production" here means apps you deploy somewhere else, such as Fly.io, that you list in the config. It reads their Dockerfile and lockfiles from the repo and never changes them. List none and it only checks your computer. |
| **Compared against** | [pwn.watch](https://pwn.watch) (broad incident feed, filtered to what you run) and [Cloudflare Radar Zero Wire](https://radar.cloudflare.com/security/zero-wire) (a short list of major threats). The agent confirms each match against the vendor's own advisory. |
| **How it tells you** | A desktop notification with a one-line summary, a short summary as the agent's final message, and a full report folder in `~/security-feed-check-runs/`. No email, Slack or cloud service. |
| **What it changes** | Nothing, by default. Set `"auto_update": true` and it may update one installed app or package when the vendor has a verified fix, for example `brew upgrade <that package>` or a closed app's own updater. Never macOS itself, a running app, a server, or anything needing `sudo`. |
| **Linux** | Feeds, runtimes, lockfiles, Homebrew if installed, and distro packages from dpkg (Debian/Ubuntu), rpm (Fedora/RHEL/SUSE), pacman (Arch) or apk (Alpine). It reports Linux package fixes; it never installs them, because that needs `sudo`. No app list. |

Anything it cannot read is reported as `UNKNOWN`, never as clean.

## Install

**Claude Code**

```
/plugin marketplace add grahac/security-feed-check
/plugin install security-feed-check@security-feed-check
```

**Codex**

```bash
codex plugin marketplace add grahac/security-feed-check
codex plugin add security-feed-check@security-feed-check
```

**Manual (either tool):** copy `skills/security-feed-check/` into `~/.claude/skills/` or `~/.codex/skills/`.

It needs a local agent because it looks at what is installed on your machine. It does not work in claude.ai or other hosted chat.

## Set up

Ask your agent: "run a security feed check". On the first run it copies the example config to `~/.config/security-feed-check/watchlist.json` and asks what you use, so the feed is filtered to your tools. To do it by hand:

```bash
mkdir -p ~/.config/security-feed-check
cp skills/security-feed-check/assets/watchlist.example.json ~/.config/security-feed-check/watchlist.json
```

Then add what you run to `tags` ([pwn.watch tag ids](https://pwn.watch/tags.json)) and `keywords`. Optionally list lockfiles and deployed project repos. Set `SECURITY_FEED_CHECK_HOME` to keep config and state somewhere else.

**macOS notifications** come from Script Editor. Allow it once in System Settings → Notifications → Script Editor, and choose Alerts so the notification stays until you dismiss it. Set `"notify": false` to turn them off.

## Run it every morning

Use whatever scheduler you like:

```bash
# cron, Claude Code
0 7 * * * claude -p "run the security-feed-check skill"

# cron, Codex (the feeds need network access)
0 7 * * * codex exec -c sandbox_workspace_write.network_access=true "run the security-feed-check skill"
```

Unattended runs need permission to run the check script; with `"auto_update": true` they also need your package manager. Allow those in your tool's permission settings.

## How it decides

1. `scripts/check.py` fetches both feeds, filters pwn.watch by your watchlist, and marks what is new since the last run.
2. `scripts/check.py inventory` lists what is installed (see the table above) and what each deployed repo ships.
3. The agent checks each candidate against the vendor's own advisory before calling it a finding. Feed text is treated as untrusted data.
4. If `auto_update` is on, it applies only the narrow updates in [`SKILL.md`](skills/security-feed-check/SKILL.md) and verifies them. Then it writes the report, records what it saw, and sends the notification.

## Development

```bash
python3 -B skills/security-feed-check/scripts/test_check.py   # offline, stdlib only
```

## License

MIT
