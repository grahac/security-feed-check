# security-feed-check

A daily "does any new vulnerability affect me?" check for [Claude Code](https://claude.com/claude-code) and [Codex](https://github.com/openai/codex).

It reads two vulnerability feeds, compares them with what is actually installed on your machine and in your deployed projects, and reports only what affects you, each with an exact fix.

- **[pwn.watch](https://pwn.watch)**: a broad incident feed with affected and fixed versions, filtered by your watchlist.
- **[Cloudflare Radar Zero Wire](https://radar.cloudflare.com/security/zero-wire)**: a short, curated list of major threats. Every "Needs attention" item is checked.

By default the agent also applies narrow local security updates when a verified vendor release fixes something you have installed: closed apps only, one package at a time, same major version, verified afterward. Set `"auto_update": false` for report-only. Production, running apps, databases, lockfiles and Git are always report-only; those go in the report for your approval.

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

The skill runs commands on your own machine to see what is installed, so it needs a local agent. It does not work in claude.ai or other hosted chat.

## Set up

```bash
mkdir -p ~/.config/security-feed-check
cp skills/security-feed-check/assets/watchlist.example.json ~/.config/security-feed-check/watchlist.json
```

Then add the tools you run to `tags` ([pwn.watch tag ids](https://pwn.watch/tags.json)) and `keywords`. Optionally list lockfiles and deployed project repos. The agent will offer to do this on the first run. Set `SECURITY_FEED_CHECK_HOME` to keep config and state somewhere else.

## Run it

Ask your agent: "run a security feed check". To run it every morning, use whatever scheduler you like:

```bash
# cron, Claude Code
0 7 * * * claude -p "run the security-feed-check skill"

# cron, Codex (the feeds need network access)
0 7 * * * codex exec -c sandbox_workspace_write.network_access=true "run the security-feed-check skill"
```

Unattended runs need permission to run the check script and your package manager; allow those in your tool's permission settings, or set `"auto_update": false` and allow just the script. Each run writes a report folder under `reports_dir` and ends with a short summary: what was updated, what needs your approval, and what is waiting on a vendor fix.

## How it decides

1. `scripts/check.py` fetches both feeds, filters pwn.watch by your watchlist, and marks what is new since the last run.
2. `scripts/check.py inventory` lists installed apps, Homebrew and global npm packages, runtimes, your lockfiles, and what each deployed repo ships.
3. The agent checks each candidate against the vendor's own advisory before calling it a finding. Feed text is treated as untrusted data.
4. It applies only the safe updates in [`SKILL.md`](skills/security-feed-check/SKILL.md), verifies them, writes the report, and then records what it saw.

If a feed fails or comes back empty, the run says so (`COVERAGE LOST`) instead of reporting all clear.

## Development

```bash
python3 -B skills/security-feed-check/scripts/test_check.py   # offline, stdlib only
```

## License

MIT
