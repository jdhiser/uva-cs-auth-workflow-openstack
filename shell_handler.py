import time
import paramiko
import sys
import socket
import os
import datetime
from typing import Tuple, Optional
from paramiko.ssh_exception import (
    SSHException,
    AuthenticationException,
    BadAuthenticationType,
    NoValidConnectionsError,
)


class ShellHandler:

    def __init__(
            self,
            host,
            user,
            password,
            from_ip: Optional[str] = None,
            verbose: bool = False,
            timeout: int = 30,
            retries: int = 10,
            base_delay: float = 5.0
    ):

        self.verbose = verbose
        self.sock = None
        if from_ip is not None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((from_ip, 0))           # set source address
            self.sock.connect((host, 22))       # connect to the destination address

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        allow_agent = True
        look_for_keys = True
        if password is not None:
            allow_agent = False
            look_for_keys = False

        for attempt in range(retries):
            try:
                self.ssh.connect(
                    host,
                    username=user,
                    password=password,
                    allow_agent=allow_agent,
                    look_for_keys=look_for_keys,
                    port=22,
                    sock=self.sock,
                    timeout=timeout,
                )
                break

            except (
                    AuthenticationException,
                    BadAuthenticationType,
                    NoValidConnectionsError,
                    SSHException,
                    OSError,
                    EOFError
            ) as e:
                if attempt < retries - 1:
                    delay = base_delay * (2 ** attempt)
                    if delay > 30:
                        delay = 30
                    print(f"  [WARN] SSH connection to {host} failed (attempt {attempt + 1}/{retries}): {e}. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                else:
                    print(f"  [ERROR] SSH connection to {host} failed after {retries} attempts: {e}")
                    raise
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
            # Read stdout if ready
            if channel.recv_ready():
                data = channel.recv(1024).decode("utf-8", errors="replace")
                stdout_buf += data
                while '\n' in stdout_buf:
                    line, stdout_buf = stdout_buf.split('\n', 1)
                    stdout_lines.append(line + '\n')
                    if verbose or self.verbose:
                        print(line)

            # Read stderr if ready
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(1024).decode("utf-8", errors="replace")
                stderr_buf += data
                while '\n' in stderr_buf:
                    line, stderr_buf = stderr_buf.split('\n', 1)
                    stderr_lines.append(line + '\n')
                    if verbose or self.verbose:
                        print(line)

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
        wrapper_contents = f"""
$OutputEncoding = [System.Text.Encoding]::UTF8
Start-Transcript -Path "{log_path}" -Force

try {{
    Write-Host "=== Starting install-iis.ps1 ==="
    $command = @'
Set-PSDebug -Trace 1
. "{script_path}"
Set-PSDebug -Trace 0
'@
    $output = powershell -ExecutionPolicy Bypass -NoProfile -Command $command *>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object {{ Write-Host $_ }}
    Write-Host "=== Finished install-iis.ps1 ==="
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

        # Ensure the target directory exists
        self.execute_cmd(f"{sudo}mkdir -p '{script_dir}'", verbose=verbose)

        # Upload the script to a temporary user-writable location
        self.put_file_from_string(tmp_path, script_contents)

        # Move the script to the final location if different
        if tmp_path != script_path:
            self.execute_cmd(f"{sudo}mv '{tmp_path}' '{script_path}'", verbose=verbose)
        else:
            script_path = tmp_path

        self.execute_cmd(f"{sudo}chmod +x '{script_path}'", verbose=verbose)

        # Run the script with stdout and stderr redirected to log
        exec_cmd = f"{sudo}stdbuf -oL bash -x '{script_path}' 2>&1 | {sudo}stdbuf -oL tee '{log_path}'"
        return self.execute_cmd(exec_cmd, verbose=verbose)
