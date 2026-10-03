#!/usr/bin/env python3
"""OpenClaw self-check. Free, read-only, runs on YOUR machine only.

    python3 openclaw-check.py            (Python 3.8+, no installs, no network calls except to your own computer)

It reads your OpenClaw config and installed skills, and checks:
  1. Gateway exposure: the bind setting, auth mode, and whether the gateway port answers on your own LAN address.
  2. Heartbeat cost: how often idle agent turns run and roughly how many tokens they send.
  3. Skills: names matching skills publicly reported as malicious, and SKILL.md files with patterns used by the
     ClawHavoc campaign.
It changes nothing, sends nothing anywhere and never scans any other machine. Read it before you run it: it's short.

Sources (checked 3 Oct 2026):
  - Gateway bind/auth defaults: https://docs.openclaw.ai/gateway/config-gateway
  - Heartbeat (default 30m; ~100K tokens per run with full history vs ~2-5K isolated):
    https://docs.openclaw.ai/gateway/heartbeat
  - Skill locations: https://docs.openclaw.ai/tools/skills
  - Malicious skill names + indicators (Koi Security via The Hacker News, 2 Feb 2026):
    https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html
"""
import json
import os
import re
import socket
import sys
from pathlib import Path

VERSION = "1.0 (3 Oct 2026)"
HOME = Path.home()
PORT_DEFAULT = 18789

# Example names from the reported list (The Hacker News, 2 Feb 2026, quoting Koi Security). Not the full 341: a match
# means "check where this came from", not proof. Generic names (update, updater) are flagged as low confidence.
REPORTED = {
    "clawhub", "clawhub1", "clawhubb", "clawhubbcli", "clawwhub", "cllawhub", "polymarket-trader", "polymarket-pro",
    "polytrading", "youtube-summarize", "youtube-thumbnail-grabber", "youtube-video-downloader", "auto-updater-agent",
    "yahoo-finance-pro", "x-trends-tracker", "solana-wallet-tracker", "youtube-summarize-pro", "better-polymarket",
    "polymarket-all-in-one", "rankaj",
}
REPORTED_GENERIC = {"update", "updater"}
# Indicators named in the same report, plus the delivery tricks it describes (fake "prerequisites" that pipe a
# downloaded or base64-decoded script into a shell, or a password-protected zip).
IOC = [
    (re.compile(r"91\.92\.242\.30"), "address 91.92.242.30 (reported ClawHavoc server)"),
    (re.compile(r"glot\.io", re.I), "glot.io link (used to host ClawHavoc scripts)"),
    (re.compile(r"webhook\.site", re.I), "webhook.site link (used to send stolen data out)"),
    (re.compile(r"openclaw-agent\.zip", re.I), "openclaw-agent.zip (reported malicious download)"),
    (re.compile(r"base64\s+(-d|--decode|-D)[^\n|]*\|\s*(\w+\s+)?(ba|z)?sh\b", re.I),
     "decodes base64 and runs it in a shell"),
    (re.compile(r"(curl|wget)[^\n|]*\|\s*(\w+\s+)?(ba|z)?sh\b", re.I), "downloads a script and runs it in a shell"),
    (re.compile(r"password[- ]protected\s+(zip|archive)|zip\s+password", re.I), "password-protected zip"),
]

RED, YEL, GRN, DIM, END = ("\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m") if sys.stdout.isatty() \
    else ("", "", "", "", "")
found = {"bad": 0, "warn": 0}


def say(level, text):
    mark = {"ok": f"{GRN}  ok {END}", "warn": f"{YEL}warn {END}", "bad": f"{RED} BAD {END}", "info": f"{DIM}info {END}"}
    if level in found:
        found[level] += 1
    print(f"  {mark[level]} {text}")


def json5_load(text):
    """Enough JSON5 for config files: comments, trailing commas, unquoted keys, single-quoted strings."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                buf.append('\\"' if text[j] == '"' else text[j])
                j += 1
            out.append('"' + "".join(buf) + '"')
            i = j + 1
        elif text.startswith("//", i):
            k = text.find("\n", i)
            i = n if k < 0 else k
        elif text.startswith("/*", i):
            k = text.find("*/", i)
            i = n if k < 0 else k + 2
        else:
            out.append(c)
            i += 1
    s = "".join(out)
    s = re.sub(r",(\s*[}\]])", r"\1", s)
    s = re.sub(r"([{,]\s*)([A-Za-z_$][\w$-]*)(\s*:)", r'\1"\2"\3', s)
    return json.loads(s)


def get(d, path, default=None):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def lan_ip():
    try:  # no packet is sent: connecting a UDP socket only picks the outgoing interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        s.close()
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


def answers(host, port):
    try:
        socket.create_connection((host, port), 1.5).close()
        return True
    except OSError:
        return False


def no_auth(mode):
    return str(mode).lower() in ("none", "off", "false")


def check_gateway(cfg):
    print("\n1. Gateway exposure")
    bind = get(cfg, "gateway.bind", "loopback")
    mode = get(cfg, "gateway.auth.mode", "token")
    port = int(get(cfg, "gateway.port", PORT_DEFAULT) or PORT_DEFAULT)
    if bind == "loopback":
        say("ok", "gateway.bind is loopback (only this computer can reach it)")
    else:
        say("warn", f"gateway.bind is \"{bind}\": other devices can reach the gateway. Keep it on loopback unless you "
                    f"need remote access, and then use a VPN/tailnet")
    if no_auth(mode):
        say("bad" if bind != "loopback" else "warn", f"gateway.auth.mode is \"{mode}\": no token on the gateway")
    else:
        say("ok", f"gateway auth mode: {mode}")
    if get(cfg, "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback"):
        say("warn", "controlUi.dangerouslyAllowHostHeaderOriginFallback is on (OpenClaw docs: use with caution)")
    ip = lan_ip()
    if not answers("127.0.0.1", port):
        say("info", f"nothing answering on port {port} right now (gateway not running?), so live exposure not tested")
    elif ip and answers(ip, port):
        say("bad" if no_auth(mode) else "warn",
            f"the gateway answers on your network address {ip}:{port}, so any device on this network can try it")
    else:
        say("ok", f"gateway answers on 127.0.0.1:{port} only" + (f", not on {ip}" if ip else ""))
    print(f"  {DIM}This only tests your own machine from itself. It can't see your router: if you forward port "
          f"{port}, it's on the internet.{END}")


def check_heartbeat(cfg):
    print("\n2. Heartbeat (idle cost)")
    hb = get(cfg, "agents.defaults.heartbeat", {}) or {}
    every = str(hb.get("every", "30m (default)"))
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([mh])", every)
    minutes = (float(m.group(1)) * (60 if m.group(2) == "h" else 1)) if m else 30.0
    if minutes == 0:
        say("ok", "heartbeat is off (every: 0m): no idle model calls")
        return
    runs = 1440 / minutes
    light = bool(hb.get("isolatedSession")) and bool(hb.get("lightContext"))
    say("info", f"heartbeat every {every}: about {runs:.0f} full agent turns a day, even when you do nothing")
    if light:
        say("ok", f"isolatedSession + lightContext on: OpenClaw docs put this at ~2-5K tokens a run "
                  f"(~{runs * 2_000 * 30 / 1e6:.1f}-{runs * 5_000 * 30 / 1e6:.1f}M input tokens a month)")
    else:
        say("warn", f"isolatedSession/lightContext not both on: OpenClaw docs say a run can send ~100K tokens of "
                    f"history, up to ~{runs * 100_000 * 30 / 1e6:.0f}M input tokens a month while idle. Turn both "
                    f"on, or set every: \"0m\" if you don't need it")


def skill_dirs(cfg):
    roots = [HOME / ".openclaw", HOME / ".agents" / "skills", HOME / ".clawdbot"]
    ws = get(cfg, "agents.defaults.workspace")
    if ws:
        roots.append(Path(os.path.expanduser(str(ws))))
    roots += [Path(os.path.expanduser(str(p))) for p in (get(cfg, "skills.load.extraDirs", []) or [])]
    seen, out = set(), []
    for root in roots:
        if not root.is_dir():
            continue
        for base, dirs, files in os.walk(root):
            depth = len(Path(base).relative_to(root).parts)
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "sessions", "logs") and depth < 6]
            if "SKILL.md" in files and Path(base).resolve() not in seen:
                seen.add(Path(base).resolve())
                out.append(Path(base))
    return out


def check_skills(cfg):
    print("\n3. Installed skills")
    dirs = skill_dirs(cfg)
    if not dirs:
        say("info", "no SKILL.md folders found under ~/.openclaw, ~/.agents/skills or your workspace")
        return
    say("info", f"{len(dirs)} skill folder(s) found")
    clean = 0
    for d in sorted(dirs):
        name = d.name.lower()
        try:
            text = (d / "SKILL.md").read_text(errors="replace")[:200_000]
        except OSError:
            text = ""
        hits = [why for rx, why in IOC if rx.search(text)]
        if name in REPORTED:
            say("bad", f"{d}: name matches a skill reported as malicious (ClawHavoc). Check where it came from")
        elif name in REPORTED_GENERIC:
            say("warn", f"{d}: generic name \"{name}\" was also used by reported malicious skills; check its source")
        if hits:
            say("bad" if name in REPORTED or len(hits) > 1 else "warn", f"{d.name}: SKILL.md contains: {'; '.join(hits)}")
        if name not in REPORTED and name not in REPORTED_GENERIC and not hits:
            clean += 1
    if clean:
        say("ok", f"{clean} skill(s) with no reported name and none of the known patterns")
    print(f"  {DIM}No list catches everything: only install skills whose SKILL.md you've read.{END}")


def main():
    print(f"OpenClaw self-check {VERSION}: read-only, this computer only")
    path = Path(os.environ.get("OPENCLAW_CONFIG_PATH") or HOME / ".openclaw" / "openclaw.json")
    cfg = {}
    if path.is_file():
        try:
            cfg = json5_load(path.read_text(errors="replace"))
            print(f"  config: {path}")
        except (ValueError, OSError) as e:
            print(f"  couldn't parse {path} ({e}); using OpenClaw's documented defaults")
    else:
        print(f"  no config at {path}; using OpenClaw's documented defaults (set OPENCLAW_CONFIG_PATH if it's elsewhere)")
    check_gateway(cfg)
    check_heartbeat(cfg)
    check_skills(cfg)
    print(f"\nResult: {found['bad']} serious, {found['warn']} to look at.")
    return 1 if found["bad"] else 0


if __name__ == "__main__":
    sys.exit(main())
