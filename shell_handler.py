import paramiko
import sys
import socket
import os
import uuid


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

    def execute_powershell_multiline(self, cmd, verbose=False, exit=False, filename: str = None):
        """
        Executes a multi-line PowerShell script on the remote Windows host
        by uploading it to C:\\tmp and executing it via powershell -File.

        Parameters:
        - cmd: str - Multi-line PowerShell script content
        - verbose: bool - If True, prints script content and execution progress
        - exit: bool - If True, terminates Python on failure
        - filename: str - Optional name to use for both local and remote script

        Returns:
        - tuple: (stdout_lines, stderr_lines, exit_status)
        """

        if not os.path.exists('./tmp'):
            os.makedirs('./tmp', exist_ok=True)

        script_name = filename if filename else f'ps_script_{uuid.uuid4().hex}.ps1'
        tmp_local_path = os.path.join('./tmp', script_name)
        tmp_remote_path = f'C:\\tmp\\{script_name}'

        with open(tmp_local_path, 'w', encoding='utf-8') as f:
            f.write(cmd)

        if verbose or self.verbose:
            print(f"Uploading PowerShell script to: {tmp_remote_path}")
            print(f"Script contents:\n{cmd}")

        # Ensure C:\tmp exists on the remote host
        self.execute_cmd('powershell -Command "New-Item -Path C:\\tmp -ItemType Directory -Force"', verbose=verbose)

        # Overwrite the file in C:\tmp
        self.put_file(tmp_local_path, tmp_remote_path)
        os.remove(tmp_local_path)

        ps_exec_cmd = f'powershell -ExecutionPolicy Bypass -File "{tmp_remote_path}"'
        stdout, stderr, exit_code = self.execute_cmd(ps_exec_cmd, verbose=verbose)

        try:
            self.sftp.remove(tmp_remote_path)
        except Exception as cleanup_err:
            if verbose or self.verbose:
                print(f"Warning: failed to delete remote script: {cleanup_err}")

        if exit:
            sys.exit(1)

        return stdout, stderr, exit_code
