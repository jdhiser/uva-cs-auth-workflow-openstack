import time
from typing import Optional
import paramiko
from shell_handler import ShellHandler

verbose = False


def wait_for_local_admin_ssh(host: str, user: str, password: str,
                             deadline_sec: int = 300, poll_sec: int = 10,
                             log_every_sec: int = 60) -> bool:
    """
    Poll until local-admin SSH is accepted on `host`, or `deadline_sec` passes.

    On a freshly-booted Windows VM, cloud-init / first-boot takes time to push
    the local administrator password into SAM and reload sshd. During that
    window, paramiko sees AuthenticationException and ShellHandler treats
    auth errors as terminal (correct in most contexts). We add a thin retry
    here so register_windows_instance doesn't fast-fail on transient bring-up.

    Logging: emits one line at start, one line at most every `log_every_sec`
    while polling (and whenever the error type changes), and one line at end.
    Passes quiet_errors=True to ShellHandler so its own [ERROR] line is
    suppressed for each attempt — this loop logs its own progress instead.

    Returns True if SSH eventually works, False if the deadline expires (e.g.
    the node is already domain-joined and the local password no longer works).
    """
    start = time.time()
    deadline = start + deadline_sec
    print(f"  [INFO] {host}: waiting for local admin SSH (up to {deadline_sec}s)")
    attempt = 0
    last_log_time = 0.0
    last_err_type: Optional[str] = None
    while time.time() < deadline:
        attempt += 1
        try:
            shell = ShellHandler(host, user, password, retries=1, verbose=False, quiet_errors=True)
            shell.execute_powershell("Write-Host ssh-ready", verbose=False)
            elapsed = int(time.time() - start)
            print(f"  [INFO] {host}: local admin SSH ready after {elapsed}s ({attempt} attempts)")
            return True
        except paramiko.ssh_exception.AuthenticationException:
            err_type = 'AuthenticationException'
            err_msg = 'auth rejected'
        except Exception as e:
            err_type = type(e).__name__
            err_msg = str(e)

        now = time.time()
        if (now - last_log_time >= log_every_sec) or (err_type != last_err_type):
            remaining = max(0, int(deadline - now))
            print(f"  [INFO] {host}: local admin SSH not ready ({err_type}: {err_msg}; "
                  f"attempt {attempt}, {remaining}s remaining)")
            last_log_time = now
            last_err_type = err_type
        time.sleep(poll_sec)
    elapsed = int(time.time() - start)
    print(f"  [INFO] {host}: local admin SSH timed out after {elapsed}s ({attempt} attempts)")
    return False


def do_rename_adapter(control_ip: str, user: str, password: str, rename_ip: str, new_name: str, metric: int):

    rename_cmd = f"""
        $ipAddr="{rename_ip}"
        $new_name="{new_name}"
        $metric={metric}
        $adapter = Get-NetIPAddress  -AddressFamily IPv4 -IPAddress $ipAddr| Select-Object -ExpandProperty InterfaceAlias
        Rename-NetAdapter -Name $adapter -NewName $new_name 
        Set-NetIPInterface -InterfaceAlias $new_name -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric $metric
        Get-NetIPInterface |
            Sort-Object InterfaceMetric |
            Format-Table InterfaceAlias, InterfaceIndex, AddressFamily, InterfaceMetric
        """

    try:
        shell = ShellHandler(control_ip, user, password, verbose=verbose, retries=1)
        stdout, stderr, exit_status = shell.execute_powershell_multiline(rename_cmd, filename=f"rename-{new_name}")
    except Exception:
        print("Could not connect with credentials to rename adapter.  Already domain-joined?")
        return {}

    return {"stdout": stdout, "stderr": stderr, "exit_status": exit_status}


def tune_sshd_settings(control_ip: str, user: str, password: str):
    """
    Relax Windows OpenSSH limits so the parallel deploy doesn't trip
    MaxStartups / MaxAuthTries throttles, which manifest as "Error reading
    SSH protocol banner" and force minutes of backoff for no good reason.

    Idempotent: reads sshd_config first, only rewrites + restarts sshd if
    any value is missing or different. On a re-run where the desired values
    are already present, prints "already set" and returns without touching
    sshd. The actual sshd restart (when needed) is spawned as a detached
    cmd.exe so it doesn't kill our own SSH session mid-write; by the time
    anything next tries to connect, sshd is back up with the new config.

    Returns dict with `stdout/stderr/exit_status` plus `applied` (True if
    the script rewrote the config + restarted, False if it was already set).
    """
    cmd = r"""
$cfg = "C:\ProgramData\ssh\sshd_config"
$wanted = [ordered]@{
    "MaxStartups"    = "1000:30:2000"
    "MaxAuthTries"   = "1000000"
    "LoginGraceTime" = "5m"
}

$current = @()
if (Test-Path $cfg) { $current = Get-Content $cfg }

$needsUpdate = $false
foreach ($k in $wanted.Keys) {
    $v = $wanted[$k]
    $expected = "^\s*$([regex]::Escape($k))\s+$([regex]::Escape($v))\s*$"
    $hit = $false
    foreach ($line in $current) {
        if ($line -match $expected) { $hit = $true; break }
    }
    if (-not $hit) { $needsUpdate = $true }
}

if (-not $needsUpdate) {
    Write-Host "TUNE-SSHD-RESULT: already-set"
    Write-Host "Done."
    exit 0
}

function Set-SshdOption([string]$name, [string]$value) {
    $cfg = "C:\ProgramData\ssh\sshd_config"
    $lines = Get-Content $cfg
    $pattern = "^\s*#?\s*$name\s+.*"
    if ($lines -match $pattern) {
        $lines = $lines -replace $pattern, "$name $value"
    } else {
        $lines += "$name $value"
    }
    Set-Content -Path $cfg -Value $lines -Encoding ASCII
}

foreach ($k in $wanted.Keys) { Set-SshdOption $k $wanted[$k] }

Write-Host "TUNE-SSHD-RESULT: applied"
Write-Host "sshd_config updated; scheduling background sshd restart."

Start-Process -WindowStyle Hidden cmd.exe -ArgumentList '/c "ping -n 4 127.0.0.1 >nul & net stop sshd & net start sshd"'

Write-Host "Done."
"""
    try:
        shell = ShellHandler(control_ip, user, password, verbose=verbose, retries=2)
        stdout, stderr, exit_status = shell.execute_powershell_multiline(cmd, filename="tune-sshd")
        applied = any("TUNE-SSHD-RESULT: applied" in line for line in (stdout or []))
        return {"stdout": stdout, "stderr": stderr, "exit_status": exit_status, "applied": applied}
    except Exception as e:
        # If the detached restart raced us, our session may have been torn
        # down before the script returned cleanly. The config write is
        # idempotent and runs first, so this is usually fine — and we
        # conservatively assume we applied (so the caller waits for sshd).
        print(f"  [INFO] sshd tune may have completed; session ended ({type(e).__name__}: {e})")
        return {"applied": True}


def confirm_domain_member(host: str, domain_name: str, leader_admin_password: str) -> bool:
    """
    Probe whether `host` is a member of `domain_name` by SSHing as
    DOMAIN\\Administrator and checking $env:userdomain. Returns True only if
    the box answers with the expected domain.

    Uses retries=1 so it fails fast on transient TCP/banner errors — this is
    a probe, not a wait-for-it-to-work call.
    """
    user = 'Administrator'
    try:
        shell = ShellHandler(host, domain_name + '\\' + user, leader_admin_password,
                             verbose=False, retries=1)
        stdout, _, _ = shell.execute_powershell(
            'echo "the domain is $env:userdomain"', verbose=False)
        return f'the domain is {domain_name.upper()}' in str(stdout)
    except Exception as e:
        print(f"  [INFO] Domain-member probe on {host} as {domain_name}\\{user} failed: {type(e).__name__}: {e}")
        return False


def register_windows_instance(obj):
    name = obj.get('name', '?')
    game_ipv4_addr = obj['game_addr']
    control_ipv4_addr = obj['control_addr']
    password = obj['password']
    domain = obj.get('domain')
    leader_admin_password = obj.get('leader_admin_password')
    user = 'Administrator'

    # Fast idempotency check: if we already know about this domain (re-run)
    # and the box answers as a member, skip register immediately instead of
    # burning the full local-admin-SSH timeout.
    if domain and leader_admin_password:
        if confirm_domain_member(control_ipv4_addr, domain, leader_admin_password):
            print(f"  {name} ({control_ipv4_addr}) already in domain {domain}; skipping register.")
            return {"skipped_reason": "confirmed_in_domain", "node_details": obj}

    # Some Windows images (notably win10) take 1-3 minutes after boot before
    # sshd accepts the cloud-supplied admin password. Wait for it, otherwise
    # the rename / license / sshd-tune steps all silently no-op and the join
    # script later runs with the default adapter names (so DNS isn't pointed
    # at the DCs and Add-Computer fails on a per-VM basis).
    if not wait_for_local_admin_ssh(control_ipv4_addr, user, password):
        # Local admin gave up. Try a second domain probe in case the box
        # joined the domain while we were waiting (shouldn't normally happen
        # mid-register, but cheap to check).
        if domain and leader_admin_password:
            if confirm_domain_member(control_ipv4_addr, domain, leader_admin_password):
                print(f"  Local admin SSH failed on {name} ({control_ipv4_addr}); confirmed member of domain {domain}. Skipping register.")
                return {"skipped_reason": "confirmed_in_domain", "node_details": obj}
            print(f"  [WARN] Local admin SSH failed on {name} ({control_ipv4_addr}) AND domain-member probe against {domain} failed. Node may be in a bad state.")
            return {"skipped_reason": "unreachable", "node_details": obj}
        print(f"  [WARN] Local admin SSH failed on {name} ({control_ipv4_addr}); no domain creds available to confirm state. Skipping register.")
        return {"skipped_reason": "no_domain_creds", "node_details": obj}

    # Tune sshd BEFORE the rename / license SSH operations, so any per-
    # connection transients (banner errors from sshd-session.exe spawn flakiness
    # on freshly-booted win10, MaxStartups drops under burst load) hit the
    # relaxed limits and shorter recovery, not the defaults. Idempotent: the
    # PS script no-ops if sshd_config already has the desired values, so a
    # re-run on an already-tuned host is essentially free (no sshd restart).
    sshd_tune = tune_sshd_settings(control_ipv4_addr, user, password)
    if sshd_tune.get("applied"):
        # The detached cmd.exe pings ~3 s, then stops + starts sshd. Wait
        # past that so the next SSH lands on the new sshd, not a dying one.
        print(f"  Waiting for sshd restart on {name} ({control_ipv4_addr})...")
        time.sleep(10)

    game_rename = do_rename_adapter(control_ipv4_addr, user, password, game_ipv4_addr, "game-adapter", 10)
    control_rename = ""
    if not game_ipv4_addr == control_ipv4_addr:
        control_rename = do_rename_adapter(control_ipv4_addr, user, password, control_ipv4_addr, "control-adapter", 50)

    cmd = (
        'slmgr.vbs /skms uvakms.eservices.virginia.edu; Start-Sleep -s 15; slmgr.vbs /ato; start-sleep -s 45; ' +
        ' Get-CimInstance SoftwareLicensingProduct -Filter "Name like \'Windows%\'" ' +
        '   | where { $_.PartialProductKey } | select Description, LicenseStatus'
    )

    try:
        shell = ShellHandler(control_ipv4_addr, user, password, verbose=verbose, retries=3)
        stdout, stderr, exit_status = shell.execute_powershell(cmd)
    except Exception:
        print("Could not connect with credentials to register windows, already domain-joined?")
        return {}

    return {
        "node_details": obj,
        "stdout": stdout,
        "stderr": stderr,
        "exit_status": exit_status,
        "game_rename": game_rename,
        "control_rename": control_rename,
        "sshd_tune": sshd_tune
    }
