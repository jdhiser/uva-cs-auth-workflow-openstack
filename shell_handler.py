import paramiko
import sys
import socket


class ShellHandler:

    def __init__(self, host, user, password, from_ip:str = None):

        self.sock = None
        if not from_ip == None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((from_ip, 0))           # set source address
            self.sock.connect((host, 22))       # connect to the destination address

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, username=user, password=password, port=22, sock=self.sock, timeout=10)
        self.sftp = self.ssh.open_sftp()


        #channel = self.ssh.invoke_shell()
        #self.stdin = channel.makefile('wb')
        #self.stdout = channel.makefile('r')

    def __del__(self):

        if hasattr(self, "ssh"):
            self.ssh.close()
        #self.channel.close()
        if not self.sock == None:
            self.sock.close()

    def execute_cmd(self, cmd, verbose=False):
        """

        :param cmd: the command to be executed on the remote computer
        :examples:  execute('ls')
                    execute('finger')
                    execute('cd folder_name')
        """

        if verbose:
            print("Final cmd to execute:" + cmd)
        stdin,stdout,stderr = self.ssh.exec_command(cmd, bufsize=4096)
        stdout_lines = [] 
        stderr_lines = [] 
        while not stdout.channel.exit_status_ready():
            #print('next iter')
            stdout_newlines=stdout.readlines()
            stdout_lines += stdout_newlines
            stderr_newlines=stderr.readlines()
            stderr_lines += stderr_newlines
            if verbose:
                for line in stdout_newlines:
                    print(line)
                for line in stderr_newlines:
                    print(line)
        

        exit_status = stdout.channel.recv_exit_status()
        stdout_newlines=stdout.readlines() #[ line for line in stdout.readlines() if line != [] ]
        stdout_lines += stdout_newlines
        stderr_newlines=stderr.readlines() # [ line for line in stderr.readlines() if line != [] ]
        stderr_lines += stderr_newlines
        #print('stdout lines = ' + str(len(stdout_lines)))
        #print('stderr lines = ' + str(len(stderr_lines)))
        if verbose:
            for line in stdout_newlines:
                print(line)
            for line in stderr_newlines:
                print(line)
        return stdout_lines, stderr_lines, exit_status 

    def execute_powershell(self, cmd, verbose=False, exit=False):
        quoted_cmd = cmd.replace('\\"', '\\"').replace("\\'", "\\").replace('"', '\\"')
        new_cmd = 'powershell -c "' + quoted_cmd + '"'
        if verbose:
            print("Unquoted command for powershell:" + cmd)
        if exit:
            sys.exit(1)
        return self.execute_cmd(new_cmd, verbose=verbose)

    def put_file(self, src_filename:str, dst_filename:str, verbose:bool= False):
        self.sftp.put(src_filename,dst_filename)
        return
