#!/usr/bin/env python3
"""
collect-logs.py
---------------
Baseline and post-action log collection with optional workflow-driven login emulation.

Updates (2025-11-04, v2):
* --logins is REQUIRED whenever any --workflow is present (validated early).
* Sanity-check ALL workflow params before baseline:
  - Validate user exists (if provided) in --logins.
  - Validate host exists (if provided) in post-deploy nodes.
  - Confirm --logins file exists and has at least one user.
* For each workflow:
  - If user/host omitted, choose at random and PRINT the selections (always visible).
  - Persist selections to per-step `workflow.meta.json`.
* Still uses only the [[user@]host=]name format for --workflow.
* Does NOT create steps/workflow-<name>-runXX directories.
* Parallelism default is per-node (effectively unlimited). Verbosity tiers unchanged.
"""

import argparse
import json
import random
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import importlib.util

# ------------------------------ dynamic import ------------------------------
emu_spec = importlib.util.spec_from_file_location("emulate_logins", Path("emulate-logins.py"))
if emu_spec is None or emu_spec.loader is None:
    raise SystemExit("Could not locate emulate-logins.py in the working directory.")
emulate_logins = importlib.util.module_from_spec(emu_spec)
emu_spec.loader.exec_module(emulate_logins)


GLOBAL_META_FOR_STEPS: Dict[str, Any] | None = None

# --------------------------------- helpers -----------------------------------
"""
Function: load_json
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Load a JSON file into a dict with error handling.
"""


def load_json(p: str) -> dict:
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[error] failed to load {p}: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return {}


"""
Function: ensure_dir
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Create directory path recursively if missing.
"""


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


"""
Function: pd_nodes
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Extract nodes list from post-deploy JSON across known layouts.
"""


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


"""
Function: pd_leaders
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Extract domain leaders mapping from enterprise JSON across known layouts.
"""


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


"""
Function: rec_domain
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Extract domain/forest string from a node record.
"""


def rec_domain(rec) -> Optional[str]:
    if not isinstance(rec, dict):
        return None
    ed = rec.get("enterprise_description") or {}
    return ed.get("domain") or rec.get("domain") or ed.get("forest")


"""
Function: leader_pass
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Find administrator/leader password from leaders mapping for a domain.
"""


def leader_pass(leaders: dict, dom: Optional[str]) -> Optional[str]:
    if not dom:
        return None
    info = leaders.get(dom) or {}
    for k in ("admin_pass", "leader_password", "admin_password", "password"):
        if info.get(k):
            return info[k]
    return None


"""
Function: os_hint_of
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Infer the OS type string from node metadata.
"""


def os_hint_of(n: dict) -> str:
    for k in ("os", "os_type", "platform", "family"):
        v = n.get(k)
        if isinstance(v, str):
            return v.lower()
    name = n.get("name", "") or n.get("hostname", "")
    return "windows" if name.lower().startswith(("win", "dc", "iis", "rootca", "subca")) else "linux"


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


"""
Function: _extract_ipv4_from_value
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Extract an IPv4 address from a string.
"""


def _extract_ipv4_from_value(v: Any) -> Optional[str]:
    if isinstance(v, str):
        m = _IP_RE.search(v)
        if m:
            return m.group(0)
    return None


"""
Function: ip_of
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Attempt to locate a node's IP by scanning common keys and nested structures.
"""


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


"""
Function: _fp
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Fingerprint a secret for logging without revealing it.
"""


def _fp(secret) -> str:
    if not secret:
        return "len=0 sha256=--------"
    import hashlib as _h
    return f"len={len(str(secret))} sha256={_h.sha256(str(secret).encode()).hexdigest()[:8]}"


# --------------------------- action parsing (NEW) ----------------------------
"""
Function: parse_workflow_token
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Parse [[user@]host=]name tokens for workflows.
"""


def parse_workflow_token(token: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Parse a single --workflow token in the format [[user@]host=]name.

    Enhanced to handle usernames that contain '@' (e.g., pclark@castle@win10-fin=workflow1):
    - We now split on the LAST '@' before '=', not the first.
    Returns (user_or_None, host_or_None, name).
    """
    token = token.strip()
    if "=" not in token:
        return (None, None, token)

    lhs, name = token.split("=", 1)
    lhs = lhs.strip()
    name = name.strip()

    # Split on the last '@' if present
    if "@" in lhs:
        user, host = lhs.rsplit("@", 1)
        user = user.strip() or None
        host = host.strip() or None
    else:
        user, host = (None, lhs or None)

    return (user, host, name)


"""
Function: parse_action_queue
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Build ordered (kind, payload) tuples from argv for workflows and impacts.
"""


def parse_action_queue(argv: List[str]) -> List[Tuple[str, Tuple[Optional[str], Optional[str], str]]]:
    """
    Extract an ordered queue of actions from argv with preserved ordering.
    Supports:
      --workflow [[user@]host=]name     (repeatable)
      --impact   name                   (repeatable)
    Returns: List of (kind, (user_or_None, host_or_None, name))
    """
    actions: List[Tuple[str, Tuple[Optional[str], Optional[str], str]]] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("--workflow", "-w"):
            if i + 1 >= len(argv):
                raise SystemExit("--workflow requires an argument in the form [[user@]host=]name")
            nxt = argv[i + 1]
            actions.append(("workflow", parse_workflow_token(nxt)))
            i += 2
            continue
        if tok == "--impact":
            if i + 1 >= len(argv):
                raise SystemExit("--impact requires a name")
            actions.append(("impact", (None, None, argv[i + 1])))
            i += 2
            continue
        i += 1
    return actions


# ----------------------------- auth & collectors -----------------------------
"""
Function: _auth_plan
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Decide credentials to connect to a node based on OS and domain.
"""


def _auth_plan(n: dict, ent_by_name: dict, leaders: dict, verbose: bool):
    """
    Build the auth plan for a node based on its OS and domain.
    Returns (name, host_ip, os_hint, user, password)
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
            f"[auth-plan] node={name} host_ip={host_ip} user={user} pw={pw_final} leader_pw={pw_leader}",
            file=sys.stderr,
            flush=True,
        )

    return name, host_ip, osl, user, pw_final


"""
Function: _download
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Fetch a remote file to a local path via ShellHandler.
"""


def _download(h, remote_path: str, local_path: Path, verbose: bool):
    ensure_dir(local_path.parent)
    try:
        h.get_file(remote_path, str(local_path), verbose=verbose)
    except TypeError:
        h.get_file(remote_path, str(local_path))


"""
Function: _collect_linux
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Collect Linux logs and system metadata into a remote tar.gz.
"""


def _collect_linux(remote_path: str, h, remote_verbose: bool) -> int:
    bash_script = r"""
set -euo pipefail
shopt -s globstar nullglob
tmpdir="$(mktemp -d /tmp/logs.XXXXXX)"
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


"""
Function: _collect_windows
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Collect Windows EVTX snapshots and XML, copy selected trees, then zip.
"""


def _collect_windows(remote_zip: str, name: str, h, remote_verbose: bool) -> int:
    """
    Function: _collect_windows
    Inputs:
        - remote_zip: Destination path for the archive on the remote Windows host (e.g., C:\tmp\logs-<node>.zip)
        - name: Node name used for staging directory naming
        - h: ShellHandler instance for remote execution and transfers
        - remote_verbose: Whether to enable verbose output from ShellHandler
    Returns:
        - int: PowerShell exit code from the remote execution
    """
    ps_script = f"""
$ErrorActionPreference = "Continue"

$DestRoot = 'C:\\tmp'
$ZipPath  = '{remote_zip}'
$Stage    = Join-Path $DestRoot ('logs-{name}')

# Reset stage and zip target
if (Test-Path -LiteralPath $Stage) {{ Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }}
New-Item -ItemType Directory -Force -Path $DestRoot,$Stage | Out-Null
if (Test-Path -LiteralPath $ZipPath) {{ Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue }}

# EVTX export directory
$EvtxDir = Join-Path $Stage 'evtx'
New-Item -ItemType Directory -Force -Path $EvtxDir | Out-Null

# Export each channel with a sanitized filename (EVTX only; no XML)
Get-WinEvent -ListLog * | ForEach-Object {{
    $chan = $_.LogName

    # Replace illegal filename characters (including slash/backslash) and collapse whitespace
    $san = $chan -replace '[\/:*?""<>|]', '_'
    $san = $san -replace '\s+', '_'

    $evtxPath = Join-Path $EvtxDir ($san + '.evtx')

    try {{
        # Clean point-in-time EVTX snapshot via Event Log API
        wevtutil epl "$chan" "$evtxPath" /ow:true
    }} catch {{
        Write-Warning ("EVTX export failed: {0}: {1}" -f $chan, $_.Exception.Message)
    }}
}}

# Copy additional trees (avoid live *.evtx/*.xml; we already exported snapshots and skip prior-run XML)
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
        $null = robocopy $p $target /E /R:0 /W:0 /NFL /NDL /NP /XJ /XF *.evtx *.xml
    }}
}}

# Zip it up (stage contains only curated content)
Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $ZipPath -Force -CompressionLevel Optimal
"""
    code, out, err = h.execute_powershell_multiline(ps_script, filename=f"baseline.collect.{name}.ps1", verbose=remote_verbose)
    if remote_verbose:
        print(f"[auth-used] method=execute_powershell_multiline code={code}", file=sys.stderr, flush=True)
    return code


"""
Function: _node_collect
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Collect logs for one node and download the resulting archive locally.
"""


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
    name, host_ip, osl, user, pw_final = _auth_plan(n, ent_by_name, leaders, local_verbose)

    if not host_ip:
        msg = f"[collect-error] node={name} missing control IP; skipping."
        print(msg, file=sys.stderr, flush=True)
        return name, False, msg

    try:
        import shell_handler  # repo module
        h = shell_handler.ShellHandler(host_ip, user, pw_final)  # type: ignore

        if osl.startswith("ubuntu") or osl == "linux":
            remote_tgz = f"/tmp/logs-{name}.tar.gz"
            _collect_linux(remote_tgz, h, remote_verbose)
            local_path = dst_dir / (f"{name}.logs.tar.gz" if is_baseline else f"{name}.after{idxnum:02d}.logs.tar.gz")
            _download(h, remote_tgz, local_path, remote_verbose)
        else:
            fixed_remote_zip = fr"C:\tmp\logs-{name}.zip"
            _collect_windows(fixed_remote_zip, name, h, remote_verbose)
            local_path = dst_dir / (f"{name}.logs.zip" if is_baseline else f"{name}.after{idxnum:02d}.logs.zip")
            _download(h, fixed_remote_zip, local_path, remote_verbose)

        if local_verbose:
            print(f"[collect-ok] node={name} saved={local_path}", file=sys.stderr, flush=True)
        return name, True, "ok"
    except Exception as e:
        msg = f"[collect-error] node={name} ip={host_ip} {type(e).__name__}: {e}"
        print(msg, file=sys.stderr, flush=True)
        return name, False, msg


"""
Function: collect_logs_parallel
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    Run per-node collections in parallel and write step metadata.
"""


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
    t0 = time.time()
    tag = f"{idxnum:02d}" if not is_baseline else "00"
    print(f"[{tag}] BEGIN LOGS {label}", flush=True)
    dst_dir = outdir / "steps" / step_dirname
    ensure_dir(dst_dir)

    try:
        if GLOBAL_META_FOR_STEPS is not None:
            (dst_dir / "enterprise.meta.json").write_text(json.dumps(GLOBAL_META_FOR_STEPS, indent=2), encoding="utf-8")
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


# ----------------------------------- main ------------------------------------
"""
Function: main
Inputs:
    (see function signature)
Returns:
    (see description)
Description:
    CLI entrypoint to run baseline and queued actions.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--post-deploy", dest="post_deploy", required=True)
    ap.add_argument("--enterprise-json", dest="enterprise_json", required=False)
    ap.add_argument(
        "-w",
        "--workflow",
        dest="workflow",
        action="append",
        help="Queue a workflow in order: --workflow [[user@]host=]name (repeatable)",
    )
    ap.add_argument(
        "--logins",
        dest="logins",
        default=None,
        help="Path to logins.json (REQUIRED if any --workflow is provided)",
    )
    ap.add_argument("--impact", dest="impact", action="append", help="Queue an impact in order: --impact NAME (repeatable)")
    ap.add_argument("-o", "--output", dest="output", default="out")
    ap.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="count",
        default=0,
        help="-v for local logs; -vv (or more) also enables remote ShellHandler verbosity",
    )
    ap.add_argument(
        "--max-workers",
        type=int,
        default=0,
        help="0 = per-node parallelism (one thread per node). Otherwise set an explicit cap.",
    )
    args, _ = ap.parse_known_args()

    # Load base JSON
    pd = load_json(args.post_deploy)
    ent = load_json(args.enterprise_json) if args.enterprise_json else {}
    nodes = pd_nodes(pd)
    leaders = pd_leaders(pd)

    if not nodes:
        raise SystemExit("No nodes found in post-deploy JSON.")

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

    global GLOBAL_META_FOR_STEPS
    GLOBAL_META_FOR_STEPS = meta

    # Build ordered action queue (from argv to preserve order)
    argv_actions = parse_action_queue(sys.argv[1:])

    # ---------------- Early sanity checks for workflows ----------------
    workflow_actions = [(k, v) for (k, v) in argv_actions if k == "workflow"]

    # -------- Preflight visibility for supplied settings (before baseline) --------
    for _, (user_opt, host_opt, wname) in workflow_actions:
        user_desc = f"supplied:{user_opt}" if user_opt else "not-supplied"
        host_desc = f"supplied:{host_opt}" if host_opt else "not-supplied"
        print(f"[preflight] workflow={wname} user={user_desc} host={host_desc}", flush=True)

    if workflow_actions:
        if not args.logins:
            raise SystemExit("--logins must be provided whenever --workflow is used.")
        if not Path(args.logins).exists():
            raise SystemExit(f"--logins file not found: {args.logins}")
        logins_doc = load_json(args.logins)
        all_users = logins_doc.get("users") or []
        if not isinstance(all_users, list) or not all_users:
            raise SystemExit(f"--logins has no users: {args.logins}")

        # Validate each workflow's specified user/host if provided
        for _, (user_opt, host_opt, wname) in workflow_actions:
            if user_opt:
                found = any((u.get("user_profile", {}) or {}).get("username") == user_opt for u in all_users)
                if not found:
                    raise SystemExit(f"User '{user_opt}' not found in {args.logins} for workflow '{wname}'.")
            if host_opt:
                if host_opt not in by_name:
                    raise SystemExit(f"Host '{host_opt}' not found in post-deploy for workflow '{wname}'.")
                if user_opt:
                    found = any((u.get("user_profile", {}) or {}).get("username") == user_opt for u in all_users)
                    if not found:
                        raise SystemExit(f"User '{user_opt}' not found in {args.logins} for workflow '{wname}'.")
                if host_opt:
                    if host_opt not in by_name:
                        raise SystemExit(f"Host '{host_opt}' not found in post-deploy for workflow '{wname}'.")

        # ---------------- Always run baseline first ----------------
    collect_logs_parallel(
        nodes,
        ent_by_name,
        leaders,
        outdir,
        local_verbose,
        remote_verbose,
        args.max_workers,
        step_dirname="baseline",
        label="baseline",
        idxnum=0,
        is_baseline=True,
    )

    # ---------------- Execute actions in order ----------------
    # Preload users (if any workflows exist) to reuse
    users_cache: List[dict] = []
    if workflow_actions:
        users_cache = (load_json(args.logins).get("users") or [])

    for idx, (kind, val) in enumerate(argv_actions, start=1):
        if kind == "workflow":
            user_opt, host_opt, wname = val

            # Resolve host
            if host_opt:
                target_name = host_opt  # already validated above
                host_sel = "specified"
            else:
                names = list(by_name.keys())
                if not names:
                    raise SystemExit("No hosts available to choose at random.")
                target_name = random.choice(names)
                host_sel = "random"

            # Resolve user
            if user_opt:
                username = user_opt
                user_sel = "specified"
                chosen_user_doc = next((u for u in users_cache if (u.get("user_profile", {}) or {}).get("username") == username), {})
            else:
                # Prefer users that declare this workflow; else any
                def _has_wf(u: dict) -> bool:
                    prof = (u.get("login_profile") or {})
                    return (wname in (prof.get("workflows") or []))
                candidates = [u for u in users_cache if _has_wf(u)] or users_cache
                chosen_user_doc = random.choice(candidates)
                username = chosen_user_doc.get("user_profile", {}).get("username")
                if not username:
                    raise SystemExit("Randomly selected user lacks user_profile.username in --logins.")
                user_sel = "random"

            # Make selection visible in logs (always)
            print(f"[{idx:02d}] emulate-login: workflow={wname} user={username} ({user_sel}) host={target_name} ({host_sel})", flush=True)

            # Prepare step dir and metadata
            step_dirname = f"after-{idx:02d}-workflow-{wname}"
            step_dir = outdir / "steps" / step_dirname
            ensure_dir(step_dir)
            logfile = str(step_dir / f"workflow.run{idx:02d}.ndjson")

            wf_meta = {
                "workflow": wname,
                "index": idx,
                "requested_user": user_opt,
                "requested_host": host_opt,
                "selected_user": username,
                "selected_host": target_name,
                "user_selection": user_sel,
                "host_selection": host_sel,
                "logins_path": args.logins,
                "seed": (int(time.time()) & 0xFFFFFFFF),
                "ts": datetime.now().isoformat(timespec="seconds"),
            }
            (step_dir / "workflow.meta.json").write_text(json.dumps(wf_meta, indent=2), encoding="utf-8")

            print(f"[{idx:02d}] BEGIN WORKFLOW {wname}", flush=True)

            # Build one login record
            login_length = 1
            login_start_dt = datetime.now()
            login_end_dt = login_start_dt + timedelta(seconds=login_length)

            login = {
                "user": username,
                "from": {"ip": "10.255.255.250"},
                "to": {"node": target_name},
                "login_start": login_start_dt.strftime("%Y-%m-%d %H:%M:%S.%f"),
                "login_end": login_end_dt.strftime("%Y-%m-%d %H:%M:%S.%f"),
                "login_length": login_length,
                "workflows": [wname],
                "selection": {"user": user_sel, "host": host_sel},
            }

            # Run emulated login (seed from wf_meta to also persist it)
            emulate_logins.emulate_login(
                number=1,
                login=login,
                user_data=users_cache,
                built=pd.get("enterprise_built", {}),
                seed=wf_meta["seed"],
                logfile=logfile,
                workflows_override=[wname],
            )

            print(f"[{idx:02d}] END   WORKFLOW {wname}", flush=True)

            # Collect after logs
            collect_logs_parallel(
                nodes,
                ent_by_name,
                leaders,
                outdir,
                local_verbose,
                remote_verbose,
                args.max_workers,
                step_dirname=step_dirname,
                label=f"after workflow {wname}",
                idxnum=idx,
                is_baseline=False,
            )

        elif kind == "impact":
            _, _, iname = val
            print(f"[{idx:02d}] BEGIN IMPACT {iname}", flush=True)
            step_dir = outdir / "steps" / f"impact-{iname}-run{idx:02d}"
            ensure_dir(step_dir)
            (step_dir / f"impact.run{idx:02d}.json").write_text(
                json.dumps({"result": "stubbed", "impact": iname, "index": idx}, indent=2),
                encoding="utf-8",
            )
            print(f"[{idx:02d}] END   IMPACT {iname} (0.1s)", flush=True)
            collect_logs_parallel(
                nodes,
                ent_by_name,
                leaders,
                outdir,
                local_verbose,
                remote_verbose,
                args.max_workers,
                step_dirname=f"after-{idx:02d}-impact-{iname}",
                label=f"after impact {iname}",
                idxnum=idx,
                is_baseline=False,
            )

    print("All steps complete.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
