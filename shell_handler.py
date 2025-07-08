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
        """

        :param cmd: the command to be executed on the remote computer
        :examples:  execute('ls')
                    execute('finger')
                    execute('cd folder_name')
        """

        if verbose or self.verbose:
            print("Final cmd to execute:" + cmd)
        stdin, stdout, stderr = self.ssh.exec_command(cmd, bufsize=0)
        stdout_lines = []
        stderr_lines = []
        while not stdout.channel.exit_status_ready():
            # print('next iter')
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

#            # Stream stdout
#            if stdout.channel.recv_ready():
#                for line in iter(lambda: stdout.readline(), ""):
#                    stdout_lines.append(line)
#                    if verbose or self.verbose:
#                        print(line, end='')  # Print each line as it arrives
#
#            # Stream stderr -- is this correct?
#            if stderr.channel.recv_ready():
#                for err_line in iter(lambda: stderr.readline(), ""):
#                    stderr_lines.append(err_line)
#                    if verbose or self.verbose:
#                        print(err_line, end='')

        exit_status = stdout.channel.recv_exit_status()
        stdout_newlines = stdout.readlines()  # [ line for line in stdout.readlines() if line != [] ]
        stdout_lines += stdout_newlines
        stderr_newlines = stderr.readlines()  # [ line for line in stderr.readlines() if line != [] ]
        stderr_lines += stderr_newlines
        # print('stdout lines = ' + str(len(stdout_lines)))
        # print('stderr lines = ' + str(len(stderr_lines)))
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

    def execute_powershell_multiline(self, script_contents: str, script_filename: str, verbose=False) -> Tuple[list[str], list[str], int]:
        """
        Executes a multi-line PowerShell script on a remote Windows machine.

        Parameters:
        - script_contents: str - The PowerShell script to run.
        - script_filename: str - A base name for the script, used to generate a unique log file name.
        - verbose: bool -- whether to do verbose output for the user.

        Returns:
        - Tuple of (stdout_lines, stderr_lines, exit_status)
        """

        # Ensure c:\tmp exists
        self.execute_powershell("New-Item -Path C:\\tmp -ItemType Directory -Force | Out-Null")

        # Generate unique suffix
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        basename = os.path.splitext(os.path.basename(script_filename))[0]
        logfile = f"C:\\tmp\\{basename}.{timestamp}.log"
        remotefile = f"C:\\tmp\\{basename}.ps1"

        # Write the script contents to the remote file
        self.put_file_from_string(remotefile, script_contents)

        # Construct the PowerShell command to run the script and capture output
        run_cmd = rf"""
            $OutputEncoding = [System.Text.Encoding]::UTF8
            Start-Transcript -Path "{logfile}" -Force
            try {{
                & "{remotefile}"
                exit $LASTEXITCODE
            }} finally {{
                Stop-Transcript
            }}
            """

        # Execute it
        stdout_lines, stderr_lines, exit_status = shell_handler.execute_powershell(run_cmd, verbose=verbose)

        return stdout_lines, stderr_lines, exit_status
