import time
import paramiko
import sys
import socket
import os
import datetime
from typing import Tuple, Optional
from paramiko.ssh_exception import SSHException


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
            except SSHException as e:
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
        stdin, stdout, stderr = self.ssh.exec_command(cmd, bufsize=0)
        stdout_lines = []
        stderr_lines = []
        while not stdout.channel.exit_status_ready():
            if stdout.channel.recv_ready():
                stdout_newlines = stdout.readlines()
                stdout_lines += stdout_newlines
                if verbose or self.verbose:
                    for line in stdout_newlines:
                        print(line)
            if stderr.channel.recv_ready():
                stderr_newlines = stderr.readlines()
                stderr_lines += stderr_newlines
                if verbose or self.verbose:
                    for line in stderr_newlines:
                        print(line)

        exit_status = stdout.channel.recv_exit_status()
        stdout_newlines = stdout.readlines()
        stdout_lines += stdout_newlines
        stderr_newlines = stderr.readlines()
        stderr_lines += stderr_newlines
        if verbose or self.verbose:
            for line in stdout_newlines:
                print(line)
            for line in stderr_newlines:
                print(line)
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

    def execute_bash_multiline(self, script_contents: str, filename: str, verbose: bool = False) -> Tuple[list[str], list[str], int]:
        """
        Executes a multi-line Bash script on a remote Linux machine and logs output to /var/log.

        Parameters:
        - script_contents: str - The Bash script to run.
        - filename: str - A base name for the script, used to generate a unique log file name. Must not include directory or extension.
        - verbose: bool -- whether to do verbose output for the user.

        Returns:
        - Tuple of (stdout_lines, stderr_lines, exit_status)
        """
        if os.path.dirname(filename):
            raise ValueError("filename must not contain directory components")
        if os.path.splitext(filename)[1]:
            raise ValueError("filename must not have a file extension")

        basename = filename
        script_dir = "/opt/shellhandler/scripts"
        script_path = f"{script_dir}/{basename}.sh"
        log_path = f"/var/log/{basename}.log"

        # Ensure the target directory exists
        self.execute_cmd(f"mkdir -p '{script_dir}'", verbose=verbose)

        # Upload the script
        self.put_file_from_string(script_path, script_contents)

        # Make the script executable
        chmod_cmd = f"chmod +x '{script_path}'"
        self.execute_cmd(chmod_cmd, verbose=verbose)

        # Run the script with output redirected
        exec_cmd = f"bash '{script_path}' > '{log_path}' 2>&1"
        return self.execute_cmd(exec_cmd, verbose=verbose)
