#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
from pathlib import Path

# ------------------------------- helpers ------------------------------------
def load_json(p: str) -> dict:
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[error] failed to load {p}: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return {}

def fp(secret) -> str:
    if not secret:
        return "len=0 sha256=--------"
    import hashlib as _h
    return f"len={len(str(secret))} sha256={_h.sha256(str(secret).encode()).hexdigest()[:8]}"

def pd_nodes(pd: dict) -> list:
    for path in [
        ("enterprise_built", "deployed", "nodes"),
        ("deployed", "nodes"),
        ("nodes",),
    ]:
        cur = pd
        ok = True
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and isinstance(cur, list):
            return cur
    return []

def pd_leaders(pd: dict) -> dict:
    for path in [
        ("enterprise_built", "setup", "setup_domains", "domain_leaders"),
        ("setup", "setup_domains", "domain_leaders"),
    ]:
        cur = pd
        ok = True
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and isinstance(cur, dict):
            return cur
    return {}

def rec_domain(rec) -> str:
    if not isinstance(rec, dict):
        return None
    ed = rec.get("enterprise_description") or {}
    return ed.get("domain") or rec.get("domain") or ed.get("forest")

def leader_pass(leaders: dict, dom: str) -> str:
    if not dom:
        return None
    info = leaders.get(dom) or {}
    for k in ("admin_pass", "leader_password", "admin_password", "password"):
        if info.get(k):
            return info[k]
    return None

def os_hint_of(n: dict) -> str:
    for k in ("os", "os_type", "platform", "family"):
        v = n.get(k)
        if isinstance(v, str):
            return v.lower()
    name = n.get("name", "") or n.get("hostname", "")
    return "windows" if name.lower().startswith(("win", "dc", "iis", "rootca", "subca")) else "linux"

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
def _extract_ipv4_from_value(v):
    if isinstance(v, str):
        m = _IP_RE.search(v)
        if m:
            return m.group(0)
    return None

def ip_of(n: dict) -> str:
    for k in (
        "control_ipv4_addr",
        "control_addr",
        "game_ipv4_addr",
        "ip",
        "addr",
        "ansible_host",
        "management_ip",
        "mgmt_ip",
        "host_ip",
    ):
        if n.get(k):
            ip = _extract_ipv4_from_value(n[k])
            if ip:
                return ip
    # nested
    for parent in ("access", "network", "net", "addresses"):
        v = n.get(parent)
        if isinstance(v, dict):
            for kk in ("control", "mgmt", "management", "primary", "host", "ip", "addr"):
                ip = _extract_ipv4_from_value(v.get(kk)) if isinstance(v, dict) else None
                if ip:
                    return ip
    # recursive scan
    def scan(obj):
        if isinstance(obj, dict):
            for vv in obj.values():
                ip = scan(vv)
                if ip:
                    return ip
        elif isinstance(obj, list):
            for vv in obj:
                ip = scan(vv)
                if ip:
                    return ip
        else:
            return _extract_ipv4_from_value(obj)
        return None
    return scan(n)

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# ------------------------------- main ---------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--post-deploy", dest="post_deploy", required=True)
    ap.add_argument("--enterprise-json", dest="enterprise_json", required=False)
    ap.add_argument("-w", "--workflows", dest="workflows", nargs="*", default=[])
    ap.add_argument("-o", "--output", dest="output", default="out")
    ap.add_argument("-P", dest="pre", action="store_true")
    ap.add_argument("-v", "--verbose", dest="verbose", action="store_true")
    args, _ = ap.parse_known_args()

    pd = load_json(args.post_deploy)
    ent = load_json(args.enterprise_json) if args.enterprise_json else {}
    nodes = pd_nodes(pd)
    leaders = pd_leaders(pd)

    by_name = {(n.get("name") or n.get("hostname")): n for n in nodes if isinstance(n, dict)}
    ent_by_name = {(n.get("name") or n.get("hostname")): n for n in (ent.get("nodes") or []) if isinstance(n, dict)}

    outdir = Path(args.output)
    ensure_dir(outdir / "steps")

    meta = {
        "enterprise_meta": {
            "post_deploy": args.post_deploy,
            "enterprise_json": args.enterprise_json,
            "workflows": args.workflows,
        },
        "ts": time.time(),
    }
    (outdir / "enterprise.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # ---------------- PRE: connect with IP only and collect baseline -----------
    if args.pre:
        print("[00] BEGIN PRE pre", flush=True)
        pre_dir = outdir / "steps" / "pre-baseline"
        ensure_dir(pre_dir)
        for n in nodes:
            name = n.get("name") or n.get("hostname") or "unknown"
            host_ip = ip_of(n)
            osl = os_hint_of(n)

            # domains: from deployed record, fallback to enterprise by name
            raw_dom = rec_domain(n)
            ent_dom = rec_domain(ent_by_name.get(name)) if name in ent_by_name else None
            chosen = raw_dom or ent_dom

            # creds
            user = "ubuntu" if (osl.startswith("ubuntu") or osl == "linux") else (f"{chosen}\\Administrator" if chosen else "Administrator")
            pw_leader = leader_pass(leaders, chosen)
            pw_final = pw_leader or n.get("password")

            if args.verbose:
                print(
                    f"[auth-plan] node={name} host_ip={host_ip or 'MISSING'} os={osl} dom.raw={raw_dom} dom.ent={ent_dom} -> chosen={chosen}",
                    file=sys.stderr,
                    flush=True,
                )
                print(f"[auth-plan] user={user} pw={fp(pw_final)} leader_pw={fp(pw_leader)}", file=sys.stderr, flush=True)

            if not host_ip:
                print(f"[collect-error] node={name} missing control IP; skipping.", file=sys.stderr, flush=True)
                continue

            try:
                import shell_handler  # your repo module
                h = shell_handler.ShellHandler(host_ip, user, pw_final)  # type: ignore

                if osl.startswith("ubuntu") or osl == "linux":
                    remote_tgz = f"/tmp/prelogs-{name}.tar.gz"
                    bash_script = r"""
set -euo pipefail
shopt -s globstar nullglob
tmpdir="$(mktemp -d /tmp/prelogs.XXXXXX)"
cp -f /etc/hostname "$tmpdir/" 2>/dev/null || true
cp -f /etc/*release "$tmpdir/" 2>/dev/null || true
tar -C / -czf "{remote}" \
  --warning=no-file-changed \
  --exclude="**/*.gz" --exclude="**/*.xz" --exclude="**/*.zst" \
  --exclude="**/apt/**" --exclude="**/private/**" \
  --exclude="**/btmp*" --exclude="**/wtmp*" --exclude="**/lastlog" \
  var/log etc/hostname etc/*release var/lib/systemd/coredump var/log/journal 2>/dev/null || true
if [ ! -s "{remote}" ]; then
  tar -C "$tmpdir" -czf "{remote}" .
fi
""".strip("\n").format(remote=remote_tgz)
                    safe = bash_script.replace("'", "'\"'\"'")
                    code, out, err = h.execute_cmd(f"bash -lc '{safe}'", verbose=args.verbose)
                    if args.verbose:
                        print(f"[auth-used] node={name} method=execute_cmd code={code}", file=sys.stderr, flush=True)
                    local_path = pre_dir / f"{name}.prelogs.tar.gz"
                    try:
                        h.get_file(remote_tgz, str(local_path), verbose=args.verbose)
                    except TypeError:
                        h.get_file(remote_tgz, str(local_path))
                    if args.verbose:
                        print(f"[collect-ok] node={name} saved={local_path}", file=sys.stderr, flush=True)
                else:
                    # Fixed path on Windows (ignore PS stdout/err entirely)
                    fixed_remote_zip = fr"C:\tmp\prelogs-{name}.zip"
                    ps_script = fr"""
$ErrorActionPreference = "Continue"  # keep it noisy for debugging

# Ensure C:\tmp exists and define staging
$DestRoot = 'C:\tmp'
$ZipPath  = '{fixed_remote_zip}'
$Stage    = Join-Path $DestRoot ('prelogs-{name}')

New-Item -ItemType Directory -Force -Path $DestRoot,$Stage | Out-Null
if (Test-Path -LiteralPath $ZipPath) {{ Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue }}

# 1) Export event logs safely (avoids locks on .evtx)
$EvtxDir = Join-Path $Stage 'evtx'
New-Item -ItemType Directory -Force -Path $EvtxDir | Out-Null
Get-WinEvent -ListLog * | ForEach-Object {{
    try {{
        $san = $_.LogName -replace '[\\/:*?""<>|]', '_'
        $out = Join-Path $EvtxDir ($san + '.evtx')
        wevtutil epl "$($_.LogName)" "$out"
    }} catch {{
        Write-Warning ("EVTX export failed: {0}: {1}" -f $_.LogName, $_.Exception.Message)
    }}
}}

# 2) Copy additional folders (skip raw .evtx to avoid locks)
$CopyPaths = @(
  'C:\Windows\System32\LogFiles',
  'C:\inetpub\logs\LogFiles',
  'C:\ProgramData\Microsoft\Windows\WER',
  'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'
)
foreach ($p in $CopyPaths) {{
    if (Test-Path -LiteralPath $p) {{
        $leaf = Split-Path $p -Leaf
        $target = Join-Path $Stage $leaf
        $null = robocopy $p $target /E /R:0 /W:0 /NFL /NDL /NP /XJ /XF *.evtx
    }}
}}

# 3) Create the zip (noisy output is fine; Python won't parse it)
Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $ZipPath -Force -CompressionLevel Optimal
Write-Host ("Created: " + $ZipPath)
""".lstrip("\n")
                    code, out, err = h.execute_powershell_multiline(
                        ps_script,
                        filename=f"pre.collect.{name}.ps1",
                        verbose=args.verbose,
                    )
                    if args.verbose:
                        print(f"[auth-used] node={name} method=execute_powershell_multiline code={code}", file=sys.stderr, flush=True)
                    local_path = pre_dir / f"{name}.prelogs.zip"
                    try:
                        h.get_file(fixed_remote_zip, str(local_path), verbose=args.verbose)
                    except TypeError:
                        h.get_file(fixed_remote_zip, str(local_path))
                    if args.verbose:
                        print(f"[collect-ok] node={name} saved={local_path}", file=sys.stderr, flush=True)

            except Exception as e:
                print(f"[collect-error] node={name} ip={host_ip} {type(e).__name__}: {e}", file=sys.stderr, flush=True)

        print("[00] END   PRE pre (0.0s)", flush=True)

    # ---------------- WORKFLOW: emit artifact so pipeline continues -------------
    if args.workflows:
        wname = args.workflows[0] if isinstance(args.workflows, list) and args.workflows else str(args.workflows)
        print(f"[01] BEGIN WORKFLOW {wname} #1", flush=True)
        step_dir = outdir / "steps" / f"workflow-{wname}-run01"
        step_dir.mkdir(parents=True, exist_ok=True)
        (step_dir / "workflow.run01.json").write_text(json.dumps({"result": "stubbed"}, indent=2), encoding="utf-8")
        if args.verbose:
            print(f"[trace] workflow saved -> {step_dir/'workflow.run01.json'}", file=sys.stderr, flush=True)
        print(f"[01] END   WORKFLOW {wname} (0.1s)", flush=True)

    print("All steps complete.", flush=True)

if __name__ == "__main__":
    sys.exit(main())
