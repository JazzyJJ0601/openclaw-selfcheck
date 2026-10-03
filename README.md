# openclaw-selfcheck

A read-only check of your own OpenClaw install. One Python file, no installs, and no network calls except to your own computer.

```sh
curl -O https://raw.githubusercontent.com/JazzyJJ0601/openclaw-selfcheck/main/openclaw-check.py
python3 openclaw-check.py
```

Python 3.8 or newer. Read it before you run it: it's about 250 lines.

## What it checks

1. **Gateway exposure.** Your gateway `bind` and `auth` settings, and whether the gateway port (default 18789) answers on your own LAN address.
2. **Heartbeat cost.** How often idle agent turns run, and roughly how many tokens each one sends, based on the OpenClaw heartbeat docs.
3. **Skills.** Installed skill names that match ones publicly reported as malicious, and `SKILL.md` files containing patterns described in the ClawHavoc reports (for example piping a download or base64 into a shell, or known indicator addresses).

Each finding is marked `ok`, `warn` or `BAD`, with what to change.

## What it doesn't do

- It changes nothing and sends nothing anywhere.
- It never scans any machine but yours.
- A skill-name match means "check where this came from", not proof. The name list covers examples from the public reports, not all of them.

## Sources

- Gateway config: https://docs.openclaw.ai/gateway/config-gateway
- Heartbeat: https://docs.openclaw.ai/gateway/heartbeat
- Skill locations: https://docs.openclaw.ai/tools/skills
- Malicious skills report (The Hacker News, 2 Feb 2026): https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html

## Licence

MIT
