import paramiko
import sys
import socket
import os
import datetime
from typing import Tuple


class ShellHandler:

    def __init__(self, host, user, password, from_ip: str = None, verbose=False, timeout=30):

        self.verbose = verbose
        self.sock = None
        if from_ip is not None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((from_ip, 0))           # set source address
            self.sock.connect((host, 22))       # connect to the destination address

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, username=user, password=password, port=22, sock=self.sock, timeout=timeout)
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

    def execute_powershell_multiline(self, script_contents: str, filename: str, verbose=False) -> Tuple[list[str], list[str], int]:
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

        # Write wrapper script that enables tracing and logging
        wrapper_contents = f"""
    $OutputEncoding = [System.Text.Encoding]::UTF8
    Start-Transcript -Path "{log_path}" -Force
    Set-PSDebug -Trace 1
    try {{
        & "{script_path}"
        exit $LASTEXITCODE
    }} finally {{
        Set-PSDebug -Trace 0
        Stop-Transcript
    }}
    """
        self.put_file_from_string(wrapper_path, wrapper_contents)

        # Run wrapper with powershell -File
        cmd = f'powershell -ExecutionPolicy Bypass -File "{wrapper_path}"'
        return self.execute_cmd(cmd, verbose=verbose)
