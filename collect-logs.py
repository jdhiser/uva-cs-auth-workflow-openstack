#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Global store for per-step metadata
GLOBAL_META_FOR_STEPS: Dict[str, Any] | None = None

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

def rec_domain(rec) -> Optional[str]:
    if not isinstance(rec, dict):
        return None
    ed = rec.get("enterprise_description") or {}
    return ed.get("domain") or rec.get("domain") or ed.get("forest")

def leader_pass(leaders: dict, dom: Optional[str]) -> Optional[str]:
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
def _extract_ipv4_from_value(v: Any) -> Optional[str]:
    if isinstance(v, str):
        m = _IP_RE.search(v)
        if m:
            return m.group(0)
    return None

def ip_of(n: dict) -> Optional[str]:
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

# ----------------------------- action parsing --------------------------------
def parse_action_queue(argv: List[str]) -> List[Tuple[str, str]]:
    """
    Extract an ordered queue of ('workflow'|'impact', value) from argv.
    Supports: --workflow X | -w X, --impact Y
    Preserves the user's ordering exactly. Values are plain (no colon parsing).
    """
    actions: List[Tuple[str, str]] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("--workflow", "-w"):
            if i + 1 < len(argv):
                actions.append(("workflow", argv[i + 1]))
                i += 2
                continue
        if tok == "--impact":
            if i + 1 < len(argv):
                actions.append(("impact", argv[i + 1]))
                i += 2
                continue
        i += 1
    return actions

# ----------------------------- auth & per-OS helpers -------------------------
def _auth_plan(n: dict, ent_by_name: dict, leaders: dict, verbose: bool):
    """
    _auth_plan
    ----------
    Build the auth plan for a node based on its OS and domain.

    Parameters:
        n: Node record dict.
        ent_by_name: Enterprise nodes by name.
        leaders: Domain leaders map.
        verbose: If True, print chosen credentials (hashed).

    Returns:
        (name, host_ip, os_hint, user, password) tuple.
    """

    name = n.get("name") or n.get("hostname") or "unknown"
    host_ip = ip_of(n)
    osl = os_hint_of(n)

    raw_dom = rec_domain(n)
    ent_dom = rec_domain(ent_by_name.get(name)) if name in ent_by_name else None
    chosen = raw_dom or ent_dom

    user = "ubuntu" if (osl.startswith("ubuntu") or osl == "linux") else (f"{chosen}\\Administrator" if chosen else "Administrator")
    pw_leader = leader_pass(leaders, chosen)
    pw_final = pw_leader or n.get("password")

    if verbose:
        print(
            f"[auth-plan] node={name} host_ip={host_ip or 'MISSING'} os={osl} dom.raw={raw_dom} dom.ent={ent_dom} -> chosen={chosen}",
            file=sys.stderr,
            flush=True,
        )
        def _fp(secret):
            if not secret:
                return "len=0 sha256=--------"
            import hashlib as _h
            return f"len={len(str(secret))} sha256={_h.sha256(str(secret).encode()).hexdigest()[:8]}"
        print(f"[auth-plan] user={user} pw={_fp(pw_final)} leader_pw={_fp(pw_leader)}", file=sys.stderr, flush=True)

    return name, host_ip, osl, user, pw_final


def _download(h, remote_path: str, local_path: Path, verbose: bool):
    """
    _download
    ---------
    Fetch a remote file to a local path using ShellHandler.get_file.

    Parameters:
        h: ShellHandler instance.
        remote_path: Source path on the remote.
        local_path: Local filesystem destination.
        verbose: If True, pass verbose to get_file when supported.

    Returns:
        None.
    """

    ensure_dir(local_path.parent)
    try:
        h.get_file(remote_path, str(local_path), verbose=verbose)
    except TypeError:
        h.get_file(remote_path, str(local_path))


def _collect_linux(remote_path: str, h, remote_verbose: bool) -> int:
    """
    _collect_linux
    --------------
    Create a tar.gz of key logs on a Linux host and place it at remote_path.

    Parameters:
        remote_path: Target tar.gz path on the remote.
        h: ShellHandler instance.
        remote_verbose: If True, pass verbose=True to execute_cmd.

    Returns:
        Exit code from the remote command.
    """

    bash_script = r"""
set -euo pipefail
shopt -s globstar nullglob
tmpdir="$(mktemp -d /tmp/baselinelogs.XXXXXX)"
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
""".strip("\n").format(remote=remote_path)
    safe = bash_script.replace("'", "'\"'\"'")
    code, out, err = h.execute_cmd(f"bash -lc '{safe}'", verbose=remote_verbose)
    if remote_verbose:
        print(f"[auth-used] method=execute_cmd code={code}", file=sys.stderr, flush=True)
    return code


def _collect_windows(remote_zip: str, name: str, h, remote_verbose: bool) -> int:
    """
    _collect_windows
    ----------------
    Export EVTX logs and useful directories on a Windows host and compress to remote_zip.

    Parameters:
        remote_zip: Destination zip path on the remote.
        name: Node name (used for filenames).
        h: ShellHandler instance.
        remote_verbose: If True, pass verbose=True to execute_powershell_multiline.

    Returns:
        Exit code from PowerShell execution.
    """

    ps_script = """
$ErrorActionPreference = "Continue"
$DestRoot = 'C:\\tmp'
$ZipPath  = '{remote_zip}'
$Stage    = Join-Path $DestRoot ('baselinelogs-{name}')

if (Test-Path -LiteralPath $Stage) {{ Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }}
New-Item -ItemType Directory -Force -Path $DestRoot,$Stage | Out-Null
if (Test-Path -LiteralPath $ZipPath) {{ Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue }}

$EvtxDir = Join-Path $Stage 'evtx'
New-Item -ItemType Directory -Force -Path $EvtxDir | Out-Null
Get-WinEvent -ListLog * | ForEach-Object {{
    try {{
        $san = $_.LogName -replace '[\\/:*?""<>|]', '_'
        $out = Join-Path $EvtxDir ($san + '.evtx')
        wevtutil epl "$($_.LogName)" "$out" /ow:true
    }} catch {{
        Write-Warning ("EVTX export failed: {{0}}: {{1}}" -f $_.LogName, $_.Exception.Message)
    }}
}}

$CopyPaths = @(
  'C:\\Windows\\System32\\LogFiles',
  'C:\\inetpub\\logs\\LogFiles',
  'C:\\ProgramData\\Microsoft\\Windows\\WER',
  'C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys'
)
foreach ($p in $CopyPaths) {{
    if (Test-Path -LiteralPath $p) {{
        $leaf = Split-Path $p -Leaf
        $target = Join-Path $Stage $leaf
        $null = robocopy $p $target /E /R:0 /W:0 /NFL /NDL /NP /XJ /XF *.evtx
    }}
}}

Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $ZipPath -Force -CompressionLevel Optimal
""".format(remote_zip=remote_zip, name=name)

    code, out, err = h.execute_powershell_multiline(ps_script, filename=f"baseline.collect.{name}.ps1", verbose=remote_verbose)
    if remote_verbose:
        print(f"[auth-used] method=execute_powershell_multiline code={code}", file=sys.stderr, flush=True)
    return code

# ----------------------------- unified collectors ----------------------------
def _node_collect(
    n: dict,
    ent_by_name: dict,
    leaders: dict,
    dst_dir: Path,
    local_verbose: bool,
    remote_verbose: bool,
    idxnum: int,
    is_baseline: bool,
):
    """
    _node_collect
    -------------
    Worker that collects logs from a single node.

    Parameters:
        n: Node record dict.
        ent_by_name: Enterprise nodes by name.
        leaders: Domain leader credentials map.
        dst_dir: Destination directory for output.
        local_verbose: Print local log lines if True.
        remote_verbose: Pass verbose=True to ShellHandler exec if True.
        idxnum: Snapshot index (0 baseline).
        is_baseline: True for baseline collection.

    Returns:
        (name, success, message) tuple for diagnostics.
    """

    """
    Per-node worker used by both baseline and post-action snapshots.
    idxnum: 0 for baseline; 1..N for after-action snapshots
    is_baseline: True for baseline; False for after-action
    """
    name, host_ip, osl, user, pw_final = _auth_plan(n, ent_by_name, leaders, local_verbose)

    if not host_ip:
        msg = f"[collect-error] node={name} missing control IP; skipping."
        print(msg, file=sys.stderr, flush=True)
        return name, False, msg

    try:
        import shell_handler  # repo module
        h = shell_handler.ShellHandler(host_ip, user, pw_final)  # type: ignore

        if osl.startswith("ubuntu") or osl == "linux":
            remote_tgz = f"/tmp/baselinelogs-{name}.tar.gz"
            _collect_linux(remote_tgz, h, remote_verbose)
            if is_baseline:
                local_path = dst_dir / f"{name}.baselinelogs.tar.gz"
            else:
                local_path = dst_dir / f"{name}.after{idxnum:02d}.baselinelogs.tar.gz"
            _download(h, remote_tgz, local_path, remote_verbose)
        else:
            fixed_remote_zip = fr"C:\tmp\baselinelogs-{name}.zip"
            _collect_windows(fixed_remote_zip, name, h, remote_verbose)
            if is_baseline:
                local_path = dst_dir / f"{name}.baselinelogs.zip"
            else:
                local_path = dst_dir / f"{name}.after{idxnum:02d}.baselinelogs.zip"
            _download(h, fixed_remote_zip, local_path, remote_verbose)

        if local_verbose:
            print(f"[collect-ok] node={name} saved={local_path}", file=sys.stderr, flush=True)
        return name, True, "ok"
    except Exception as e:
        msg = f"[collect-error] node={name} ip={host_ip} {type(e).__name__}: {e}"
        print(msg, file=sys.stderr, flush=True)
        return name, False, msg


def collect_logs_parallel(
    nodes: list,
    ent_by_name: dict,
    leaders: dict,
    outdir: Path,
    local_verbose: bool,
    remote_verbose: bool,
    args_max_workers: int,
    step_dirname: str,
    label: str,
    idxnum: int,
    is_baseline: bool,
):
    """
    collect_logs_parallel
    ---------------------
    Run a parallel log collection across all nodes for either baseline (idx 0)
    or after-action snapshots (idx >= 1).

    Parameters:
        nodes: List of node dicts to collect from.
        ent_by_name: Node lookup from enterprise.json by name.
        leaders: Domain leader credentials map.
        outdir: Output directory root.
        local_verbose: If True, print local progress/debug lines.
        remote_verbose: If True, pass verbose=True to ShellHandler methods.
        args_max_workers: 0 for per-node parallel; otherwise explicit cap.
        step_dirname: Steps/<dirname> destination.
        label: Human-readable label for logging.
        idxnum: 0 for baseline; 1..N for after-action snapshots.
        is_baseline: True if this is the baseline phase.

    Returns:
        None. Writes artifacts under outdir/steps/.
    """

    """
    Unified parallel collector for both baseline and after-action phases.
    - step_dirname: directory under steps/ to place outputs
    - label: human-readable label for BEGIN/END lines
    - idxnum: 0 for baseline; 1..N for after-action steps
    - is_baseline: True for baseline phase
    """
    t0 = time.time()
    tag = f"{idxnum:02d}" if not is_baseline else "00"
    print(f"[{tag}] BEGIN LOGS {label}", flush=True)
    dst_dir = outdir / "steps" / step_dirname
    ensure_dir(dst_dir)

    # Write metadata alongside the logs for this step if available
    try:
        from json import dumps as _jdumps
        if GLOBAL_META_FOR_STEPS is not None:
            (dst_dir / "enterprise.meta.json").write_text(_jdumps(GLOBAL_META_FOR_STEPS, indent=2), encoding="utf-8")
    except Exception as _e:
        print(f"[warn] failed to write step metadata: {type(_e).__name__}: {_e}", flush=True)

    max_workers = (args_max_workers if args_max_workers > 0 else max(1, len(nodes)))
    futures = []
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=f"collect-{tag}") as ex:
        for n in nodes:
            futures.append(ex.submit(_node_collect, n, ent_by_name, leaders, dst_dir, local_verbose, remote_verbose, idxnum, is_baseline))

        for fut in as_completed(futures):
            _ = fut.result()

    dt = time.time() - t0
    print(f"[{tag}] END   LOGS {label} ({dt:.1f}s)", flush=True)
def collect_action_logs(nodes: list, ent_by_name: dict, leaders: dict, outdir: Path, verbose: bool, step_dirname: str, label: str, idxnum: int):
    # Collect logs exactly like baseline, but into a unique step dir + filenames
    print(f"[{idxnum:02d}] BEGIN LOGS {label}", flush=True)
    dst_dir = outdir / "steps" / step_dirname
    ensure_dir(dst_dir)
    for n in nodes:
        name = n.get("name") or n.get("hostname") or "unknown"
        host_ip = ip_of(n)
        osl = os_hint_of(n)

        raw_dom = rec_domain(n)
        ent_dom = rec_domain(ent_by_name.get(name)) if name in ent_by_name else None
        chosen = raw_dom or ent_dom

        user = "ubuntu" if (osl.startswith("ubuntu") or osl == "linux") else (f"{chosen}\\Administrator" if chosen else "Administrator")
        pw_leader = leader_pass(leaders, chosen)
        pw_final = pw_leader or n.get("password")

        if not host_ip:
            print(f"[collect-error] node={name} missing control IP; skipping.", file=sys.stderr, flush=True)
            continue

        try:
            import shell_handler  # your repo module
            h = shell_handler.ShellHandler(host_ip, user, pw_final)  # type: ignore

            if osl.startswith("ubuntu") or osl == "linux":
                remote_tgz = f"/tmp/baselinelogs-{name}.tar.gz"
                bash_script = r"""
set -euo pipefail
shopt -s globstar nullglob
tmpdir="$(mktemp -d /tmp/baselinelogs.XXXXXX)"
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
                h.execute_cmd(f"bash -lc '{safe}'", verbose=verbose)
                local_path = dst_dir / f"{name}.after{idxnum:02d}.baselinelogs.tar.gz"
                try:
                    h.get_file(remote_tgz, str(local_path), verbose=verbose)
                except TypeError:
                    h.get_file(remote_tgz, str(local_path))
            else:
                fixed_remote_zip = fr"C:\tmp\baselinelogs-{name}.zip"
                ps_script = fr"""
$ErrorActionPreference = "Continue"
$DestRoot = 'C:\tmp'
$ZipPath  = '{fixed_remote_zip}'
$Stage    = Join-Path $DestRoot ('baselinelogs-{name}')

if (Test-Path -LiteralPath $Stage) {{ Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }}
New-Item -ItemType Directory -Force -Path $DestRoot,$Stage | Out-Null
if (Test-Path -LiteralPath $ZipPath) {{ Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue }}

$EvtxDir = Join-Path $Stage 'evtx'
New-Item -ItemType Directory -Force -Path $EvtxDir | Out-Null
Get-WinEvent -ListLog * | ForEach-Object {{ try {{ $san = $_.LogName -replace '[\\/:*?""<>|]', '_' ; $out = Join-Path $EvtxDir ($san + '.evtx') ; wevtutil epl \"$( $_.LogName )\" \"$out\" }} catch {{ }} }}
$CopyPaths = @('C:\Windows\System32\LogFiles','C:\inetpub\logs\LogFiles','C:\ProgramData\Microsoft\Windows\WER','C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys')
foreach ($p in $CopyPaths) {{ if (Test-Path -LiteralPath $p) {{ $leaf = Split-Path $p -Leaf ; $target = Join-Path $Stage $leaf ; $null = robocopy $p $target /E /R:0 /W:0 /NFL /NDL /NP /XJ /XF *.evtx }} }}

Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $ZipPath -Force -CompressionLevel Optimal
""".lstrip("\n")
                h.execute_powershell_multiline(ps_script, filename=f"after{idxnum:02d}.collect.{name}.ps1", verbose=remote_verbose)
                local_path = dst_dir / f"{name}.after{idxnum:02d}.baselinelogs.zip"
                try:
                    h.get_file(fixed_remote_zip, str(local_path), verbose=verbose)
                except TypeError:
                    h.get_file(fixed_remote_zip, str(local_path))
        except Exception as e:
            print(f"[collect-error] node={name} ip={host_ip} {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    print(f"[{idxnum:02d}] END   LOGS {label} (0.0s)", flush=True)

# ------------------------------- main ---------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--post-deploy", dest="post_deploy", required=True)
    ap.add_argument("--enterprise-json", dest="enterprise_json", required=False)
    ap.add_argument("-w", "--workflow", dest="workflow", action="append",
                    help="Queue a workflow in order: --workflow NAME (repeatable)")
    ap.add_argument("--impact", dest="impact", action="append",
                    help="Queue an impact in order: --impact NAME (repeatable)")
    ap.add_argument("-o", "--output", dest="output", default="out")
    ap.add_argument("-v", "--verbose", dest="verbose", action="count", default=0,
                    help="-v for local logs; -vv (or more) also enables remote ShellHandler verbosity")
    ap.add_argument("--max-workers", type=int, default=0,
                    help="0 = per-node parallelism (one thread per node). Otherwise set an explicit cap.")
    args, _ = ap.parse_known_args()

    # Load meta
    pd = load_json(args.post_deploy)
    ent = load_json(args.enterprise_json) if args.enterprise_json else {}
    nodes = pd_nodes(pd)
    leaders = pd_leaders(pd)

    by_name = {(n.get("name") or n.get("hostname")): n for n in nodes if isinstance(n, dict)}
    ent_by_name = {(n.get("name") or n.get("hostname")): n for n in (ent.get("nodes") or []) if isinstance(n, dict)}

    local_verbose: bool = args.verbose >= 1
    remote_verbose: bool = args.verbose >= 2
    outdir = Path(args.output)
    ensure_dir(outdir / "steps")

    # Compose meta
    meta = {
        "enterprise_meta": {
            "post_deploy": args.post_deploy,
            "enterprise_json": args.enterprise_json,
        },
        "ts": time.time(),
    }
    (outdir / "enterprise.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # expose meta to collectors without altering function signatures
    global GLOBAL_META_FOR_STEPS
    GLOBAL_META_FOR_STEPS = meta

    # Build ordered action queue from argv to preserve interleaving (ONLY from sys.argv for order)
    argv_actions = parse_action_queue(sys.argv[1:])

    # Always run baseline first
    collect_logs_parallel(nodes, ent_by_name, leaders, outdir,
                      local_verbose, remote_verbose, args.max_workers,
                      step_dirname='baseline', label='baseline', idxnum=0, is_baseline=True)

    # Run 0..N actions in given order, collecting logs after each
    for idx, (kind, val) in enumerate(argv_actions, start=1):
        if kind == "workflow":
            wname = val
            print(f"[{idx:02d}] BEGIN WORKFLOW {wname}", flush=True)
            if local_verbose:
                print(f"[workflow] running '{wname}' (stub) -> steps/workflow-{wname}-run{idx:02d}", file=sys.stderr, flush=True)
            step_dir = outdir / "steps" / f"workflow-{wname}-run{idx:02d}"
            step_dir.mkdir(parents=True, exist_ok=True)
            (step_dir / f"workflow.run{idx:02d}.json").write_text(
                json.dumps({"result": "stubbed", "workflow": wname, "index": idx}, indent=2),
                encoding="utf-8",
            )
            print(f"[{idx:02d}] END   WORKFLOW {wname} (0.1s)", flush=True)
            collect_logs_parallel(nodes, ent_by_name, leaders, outdir,
                      local_verbose, remote_verbose, args.max_workers,
                      step_dirname=f"after-{idx:02d}-workflow-{wname}",
                      label=f"after workflow {wname}", idxnum=idx, is_baseline=False)
        elif kind == "impact":
            iname = val
            print(f"[{idx:02d}] BEGIN IMPACT {iname}", flush=True)
            if local_verbose:
                print(f"[impact] applying '{iname}' (stub) -> steps/impact-{iname}-run{idx:02d}", file=sys.stderr, flush=True)
            step_dir = outdir / "steps" / f"impact-{iname}-run{idx:02d}"
            step_dir.mkdir(parents=True, exist_ok=True)
            (step_dir / f"impact.run{idx:02d}.json").write_text(
                json.dumps({"result": "stubbed", "impact": iname, "index": idx}, indent=2),
                encoding="utf-8",
            )
            print(f"[{idx:02d}] END   IMPACT {iname} (0.1s)", flush=True)
            collect_logs_parallel(nodes, ent_by_name, leaders, outdir,
                      local_verbose, remote_verbose, args.max_workers,
                      step_dirname=f"after-{idx:02d}-impact-{iname}",
                      label=f"after impact {iname}", idxnum=idx, is_baseline=False)

    print("All steps complete.", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
