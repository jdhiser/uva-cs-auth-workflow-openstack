from __future__ import annotations
import time
import paramiko
import sys
import socket
import os
import datetime
from typing import Optional, Dict, Tuple
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    NoValidConnectionsError,
    SSHException,
)


def is_auth_failure(error: Exception) -> bool:
    """
    True if the error indicates wrong credentials / unsupported auth method.

    These are not transient; retrying just provokes more failed-auth events
    and can trigger account lockout or server-side rate limiting.
    """
    return isinstance(error, (AuthenticationException, BadAuthenticationType))


def is_banner_error(error: Exception) -> bool:
    """
    True if the error indicates the SSH transport closed before auth completed
    (banner read failure, EOF, connection reset). On Windows OpenSSH this is
    typically the result of the server rate-limiting after too many failed
    attempts; the cure is a long wait, not a fast retry.
    """
    if isinstance(error, EOFError):
        return True
    if isinstance(error, SSHException):
        msg = str(error).lower()
        if "error reading ssh protocol banner" in msg:
            return True
        if "connection reset by peer" in msg:
            return True
    return False


def ssh_backoff(
    attempt: int,
    retries: int,
    base_delay: float,
    host: str,
    error: Exception,
    quiet: bool = False,
) -> None:
    """
    Handle backoff delay and logging for failed attempts.

    Parameters:
        attempt: Zero-based attempt index within the retry loop.
        retries: Total number of attempts allowed.
        base_delay: Base delay seconds for exponential backoff.
        host: Target host, for logging.
        error: The exception that caused the failure.
        quiet: When True, suppress WARN/ERROR prints (caller will log instead).
    Returns:
        None. Either sleeps for the backoff duration, or raises the final error.
    """
    if attempt < retries - 1:
        delay = min(60.0, base_delay * (2 ** attempt))
        if not quiet:
            print(
                f"  [WARN] SSH connection to {host} failed on attempt {attempt + 1}/{retries}: "
                f"{error}. Retrying in {delay:.1f}s..."
            )
        time.sleep(delay)
    else:
        if not quiet:
            print(
                f"  [ERROR] SSH connection to {host} failed after {retries} attempts: {error}"
            )
        raise error


def banner_backoff(
    attempt: int,
    retries: int,
    host: str,
    error: Exception,
    quiet: bool = False,
) -> None:
    """
    Long backoff for SSH banner / transport errors.

    The server is almost certainly rate-limiting (Windows OpenSSH after a
    failed-auth burst, fail2ban-equivalents, MaxStartups etc.). Use a much
    larger base delay and a higher cap than the generic backoff, so we wait
    long enough for the rate limit to clear instead of poking it again.
    """
    if attempt < retries - 1:
        delay = min(600.0, 60.0 * (2 ** attempt))
        if not quiet:
            print(
                f"  [WARN] SSH banner/transport error from {host} on attempt {attempt + 1}/{retries}: "
                f"{error}. Server is likely rate-limiting; sleeping {delay:.1f}s before retry..."
            )
        time.sleep(delay)
    else:
        if not quiet:
            print(
                f"  [ERROR] SSH banner/transport error from {host} persisted after {retries} attempts: {error}"
            )
        raise error


def try_connect(
    ssh: paramiko.SSHClient,
    base_params: Dict[str, object],
    overrides: Dict[str, object],
    label: str,
    verbose: bool,
) -> Tuple[bool, Optional[Exception]]:
    """
    Attempt a connection using provided param overrides.

    Parameters:
        ssh: The SSHClient instance to use.
        base_params: Shared kwargs for SSHClient.connect().
        overrides: Per-attempt overrides (e.g., password, allow_agent flags).
        label: Human-friendly label for logs (e.g., "password", "agent/keys").
        verbose: Whether to print informational/debug logs.
    Returns:
        (success_flag, error) where error is the exception if failed.
    """
    params = dict(base_params)
    params.update(overrides)

    try:
        ssh.connect(**params)
        if verbose:
            print(
                f"  [INFO] SSH connected ({label}) to "
                f"{params.get('hostname')}:{params.get('port')}"
            )
        return True, None
    except (
        AuthenticationException,
        BadAuthenticationType,
        NoValidConnectionsError,
        SSHException,
        OSError,
        EOFError,
    ) as e:
        if verbose:
            print(f"  [DEBUG] {label} auth failed: {e}")
        return False, e


class ShellHandler:
    """
    Manage an SSH/SFTP session with optional source-IP binding and robust retry logic.

    For each *retry attempt*:
      1) Try password auth (if provided).
      2) If that fails, immediately try agent/keys.
    Then (if both fail) sleep with capped exponential backoff and try again.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: Optional[str],
        from_ip: Optional[str] = None,
        verbose: bool = False,
        timeout: int = 30,
        retries: int = 10,
        base_delay: float = 5.0,
        port: int = 22,
        quiet_errors: bool = False,
    ) -> None:
        # If True, suppress this handler's [WARN]/[ERROR] prints on auth /
        # banner / connection failures — for use by callers that wrap the
        # handler in their own polling loop and emit their own progress lines
        # (e.g. role_register.wait_for_local_admin_ssh). The exception is
        # still raised; only the in-handler print is silenced.
        self.quiet_errors = quiet_errors
        self.verbose = verbose
        self.sock: Optional[socket.socket] = None

        # Optional source address binding
        if from_ip is not None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((from_ip, 0))
            self.sock.connect((host, port))  # Paramiko accepts a pre-connected socket

        base_params: Dict[str, object] = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": timeout,
            "sock": self.sock,
            # Default to disabling agent/key use unless explicitly enabled
            "allow_agent": False,
            "look_for_keys": False,
        }

        last_error: Optional[Exception] = None
        self.ssh: Optional[paramiko.SSHClient] = None
        for attempt in range(retries):
            if self.verbose:
                print(f"  [INFO] SSH connect attempt {attempt + 1}/{retries} to {host}:{port}")

            # Construct a fresh SSHClient per attempt. Reusing a client across
            # retries can leave stale paramiko transport / auth-handler state
            # from a prior failed attempt, which surfaces as e.g.
            # "TypeError: object of type 'NoneType' has no len()" out of
            # auth_handler._parse_service_accept (self.username cleared while
            # a late message from the previous attempt is still being
            # dispatched on the transport thread).
            if self.ssh is not None:
                try:
                    self.ssh.close()
                except Exception:
                    pass
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connected = False

            # Try password auth first (if provided)
            if self.verbose:
                print("  [INFO] Trying password auth")
            connected, last_error = try_connect(
                self.ssh,
                base_params,
                {"password": password, "allow_agent": True, "look_for_keys": True},
                "password",
                self.verbose,
            )

            # If password not used or failed, try agent/keys
#            if not connected:
#                if self.verbose:
#                    print("  [INFO] Trying key auth")
#                connected, last_error = try_connect(
#                    self.ssh,
#                    base_params,
#                    {"allow_agent": True, "look_for_keys": True},
#                    "agent/keys",
#                    self.verbose,
#                )

            if connected:
                if self.verbose:
                    print("  [INFO] Connected!")
                break

            err = last_error or SSHException("unknown error")

            # Auth failures aren't transient — wrong creds / disallowed method.
            # Re-attempting just generates more failed-auth events on the server,
            # which can trigger account lockout or SSH rate limiting.
            if is_auth_failure(err):
                if not self.quiet_errors:
                    print(
                        f"  [ERROR] SSH authentication to {host} failed: {err}. "
                        "Not retrying (auth errors are not transient)."
                    )
                raise err

            # Banner / transport errors: server is likely rate-limiting. Use a
            # much longer backoff so we don't keep poking it.
            if is_banner_error(err):
                banner_backoff(attempt, retries, host, err, quiet=self.quiet_errors)
            else:
                ssh_backoff(attempt, retries, base_delay, host, err, quiet=self.quiet_errors)

        # Open SFTP after successful SSH connect
        self.sftp = self.ssh.open_sftp()

    def __del__(self):

        if hasattr(self, "ssh"):
            self.ssh.close()
            self.ssh = None

        if self.sock is not None:
            self.sock.close()

    def execute_cmd(self, cmd, verbose=False):
        if verbose or self.verbose:
            print("Final cmd to execute:" + cmd)

#        stdin, stdout, stderr = self.ssh.exec_command(cmd, bufsize=0, get_pty=True)
#        channel = stdout.channel
        transport = self.ssh.get_transport()
        channel = transport.open_session()
        channel.get_pty(width=300, height=200)
        channel.exec_command(cmd)
        channel.makefile('r')
        channel.makefile_stderr('r')

        stdout_lines = []
        stderr_lines = []

        stdout_buf = ""
        stderr_buf = ""

        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            got_data = False

            # Read stdout if ready
            if channel.recv_ready():
                data = channel.recv(1024).decode("utf-8", errors="replace")
                if data:
                    got_data = True
                    stdout_buf += data
                    while '\n' in stdout_buf:
                        line, stdout_buf = stdout_buf.split('\n', 1)
                        stdout_lines.append(line + '\n')
                        if verbose or self.verbose:
                            print(line)

            # Read stderr if ready
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(1024).decode("utf-8", errors="replace")
                if data:
                    got_data = True
                    stderr_buf += data
                    while '\n' in stderr_buf:
                        line, stderr_buf = stderr_buf.split('\n', 1)
                        stderr_lines.append(line + '\n')
                        if verbose or self.verbose:
                            print(line)

            # Only back off when the remote has nothing for us right now. While
            # data is flowing (chatty scripts, large Expand-Archive trace
            # output, etc.), this loop pulls 1 KB / iter at memory speed
            # rather than ~10 KB/s. On the worst observed script (the
            # win10 install_human_windows that produced ~16 MB of PSDebug
            # trace), the old 100 ms-per-iter sleep cost ~25 min of wall-time
            # purely to drain stdout; this change drops that to seconds.
            if not got_data:
                time.sleep(0.1)

        # Flush any remaining partial lines
        if stdout_buf:
            stdout_lines.append(stdout_buf)
            if verbose or self.verbose:
                print(stdout_buf, end="")

        if stderr_buf:
            stderr_lines.append(stderr_buf)
            if verbose or self.verbose:
                print(stderr_buf, end="")

        exit_status = channel.recv_exit_status()
        return stdout_lines, stderr_lines, exit_status

    def execute_powershell(self, cmd, verbose=False, exit=False):
        quoted_cmd = cmd.replace('\\"', '\\"').replace("\\'", "\\").replace('"', '\\"')
        new_cmd = 'powershell -c "' + quoted_cmd + '"'
        if verbose or self.verbose:
            print("Unquoted command for powershell:" + cmd)
        if exit:
            sys.exit(1)
        return self.execute_cmd(new_cmd, verbose=verbose)

    def put_file(self, src_filename: str, dst_filename: str):
        self.sftp.put(src_filename, dst_filename)
        return

    def get_file(self, src_filename: str, dst_filename: str):
        self.sftp.get(src_filename, dst_filename)
        return

    def put_file_from_string(self, dst_filename: str, content: str):
        """
        Write string content to a remote file via SFTP.

        Parameters:
        - dst_filename: str - Destination path on remote system
        - content: str - File content to write
        """
        with self.sftp.file(dst_filename, mode='w') as remote_file:
            remote_file.write(content)
        return

    def get_file_to_string(self, src_filename: str) -> str:
        """
        Read the contents of a remote file into a string.

        Parameters:
        - src_filename: str - Path to the file on the remote system

        Returns:
        - str: File content as a string
        """
        with self.sftp.file(src_filename, mode='r') as remote_file:
            return remote_file.read().decode('utf-8')

    def execute_powershell_multiline(self, script_contents: str, filename: str, verbose: bool = False) -> Tuple[list[str], list[str], int]:
        """
        Executes a multi-line PowerShell script on a remote Windows machine with tracing and logging.

        Parameters:
        - script_contents: str - The PowerShell script to run.
        - filename: str - A base name for the script, used to generate a unique log file name.
        - verbose: bool -- whether to do verbose output for the user.

        Returns:
        - Tuple of (stdout_lines, stderr_lines, exit_status)
        """
        self.execute_powershell("New-Item -Path C:\\tmp -ItemType Directory -Force | Out-Null")

        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        basename = os.path.splitext(os.path.basename(filename))[0]
        log_path = f"C:\\tmp\\{basename}.{timestamp}.log"
        script_path = f"C:\\tmp\\{basename}.ps1"
        wrapper_path = f"C:\\tmp\\{basename}_wrapper.ps1"

        # Write actual user script
        self.put_file_from_string(script_path, script_contents)

        # Write wrapper script that enables tracing and logging in the child script
        # NOTE: do NOT capture the child's output into a variable before
        # printing. The caller may be on a timeout (e.g. CI's `timeout 100
        # ./emulate-logins.py ...`) and needs partial progress streamed back
        # live. Buffering into $output meant a 95s script + 5s of tee delivery
        # produced "=== Starting ps1 ===" then 100s of silence then SIGTERM —
        # losing every workflow-level success record the inner script emitted.
        # *>&1 keeps PowerShell's warning/verbose/debug streams folded into
        # stdout so paramiko receives one ordered stream.
        wrapper_contents = f"""
$OutputEncoding = [System.Text.Encoding]::UTF8
Start-Transcript -Path "{log_path}" -Force

try {{
    Write-Host "=== Starting ps1 ==="
    $command = @'
Set-PSDebug -Trace 1
. "{script_path}"
Set-PSDebug -Trace 0
'@
    powershell -ExecutionPolicy Bypass -NoProfile -Command $command *>&1
    $exitCode = $LASTEXITCODE

    Write-Host "=== Finished ps1 ==="
    exit $exitCode
}} finally {{
    Stop-Transcript
}}
"""
        self.put_file_from_string(wrapper_path, wrapper_contents)

        # Run wrapper with powershell -File
        cmd = f'powershell -ExecutionPolicy Bypass -File "{wrapper_path}"'
        return self.execute_cmd(cmd, verbose=verbose)

    def execute_bash_multiline(
        self,
        script_contents: str,
        filename: str,
        verbose: bool = False,
        path: Optional[str] = None,
        use_sudo: bool = True
    ) -> Tuple[list[str], list[str], int]:
        """
        Executes a multi-line Bash script on a remote Linux machine and logs output to a file.

        Parameters:
        - script_contents: str - The Bash script to run.
        - filename: str - A base name for the script, used to generate a unique log file name. Must not include directory or extension.
        - verbose: bool -- whether to do verbose output for the user.
        - path: Optional[str] - Directory where the script and log will be stored. Defaults to /opt/shellhandler/scripts and /var/log.
        - use_sudo: bool - Whether to use sudo for moving, chmodding, and executing the script.

        Returns:
        - Tuple of (stdout_lines, stderr_lines, exit_status)
        """
        if os.path.dirname(filename):
            raise ValueError("filename must not contain directory components")
        if os.path.splitext(filename)[1]:
            raise ValueError("filename must not have a file extension")

        basename = filename
        if path is None:
            script_dir = "/opt/shellhandler/scripts"
            log_dir = "/var/log"
        else:
            script_dir = path.rstrip("/")
            log_dir = path.rstrip("/")

        script_path = f"{script_dir}/{basename}.sh"
        log_path = f"{log_dir}/{basename}.log"
        tmp_path = f"/tmp/{basename}.sh"
        sudo = "sudo " if use_sudo else ""

        # Prepend a PS4 setting so every `set -x` traced line is prefixed with
        # a wall-clock time. Without this the trace shows what ran but not
        # when, and a multi-minute `apt install` looks identical to a 5-second
        # one. Cheap, automatic for every bash caller.
        timestamped_contents = (
            "export PS4='+ $(date \"+%H:%M:%S\") '\n"
            + script_contents
        )

        # Ensure the target directory exists
        self.execute_cmd(f"{sudo}mkdir -p '{script_dir}'", verbose=verbose)

        # Upload the script to a temporary user-writable location
        self.put_file_from_string(tmp_path, timestamped_contents)

        # Move the script to the final location if different
        if tmp_path != script_path:
            self.execute_cmd(f"{sudo}mv '{tmp_path}' '{script_path}'", verbose=verbose)
        else:
            script_path = tmp_path

        self.execute_cmd(f"{sudo}chmod +x '{script_path}'", verbose=verbose)

        # Run the script with stdout and stderr redirected to log
        exec_cmd = f"{sudo}stdbuf -oL bash -x '{script_path}' 2>&1 | {sudo}stdbuf -oL tee '{log_path}'"
        return self.execute_cmd(exec_cmd, verbose=verbose)
