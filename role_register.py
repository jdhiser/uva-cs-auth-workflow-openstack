from shell_handler import ShellHandler
import paramiko

verbose = False


def do_rename_adapter(control_ip: str, user: str, password: str, rename_ip: str, new_name: str):

    rename_cmd = (
        '$ipAddr="{}"; '.format(rename_ip) +
        '$new_name="{}"; '.format(new_name) +
        '$adapter = Get-NetIPAddress -IPAddress $ipAddr| Select-Object -ExpandProperty InterfaceAlias ;  ' +
        'Rename-NetAdapter -Name $adapter -NewName $new_name ; ' +
        'write-output "It worked!" '
    )

    try:
        shell = ShellHandler(control_ip, user, password, verbose=verbose)
        stdout, stderr, exit_status = shell.execute_powershell(rename_cmd)
    except paramiko.ssh_exception.AuthenticationException:
        print("Could not connect with credentials to rename adapter.  Already domain-joined?")
        return {}

    return {"stdout": stdout, "stderr": stderr, "exit_status": exit_status}


def register_windows_instance(obj):
    game_ipv4_addr = obj['game_addr']
    control_ipv4_addr = obj['control_addr']
    password = obj['password']
    user = 'Administrator'

    game_rename = do_rename_adapter(control_ipv4_addr, user, password, game_ipv4_addr, "game-adapter")
    control_rename = ""
    if not game_ipv4_addr == control_ipv4_addr:
        control_rename = do_rename_adapter(control_ipv4_addr, user, password, control_ipv4_addr, "control-adapter")

    cmd = (
        'slmgr.vbs /skms uvakms.eservices.virginia.edu; Start-Sleep -s 15; slmgr.vbs /ato; start-sleep -s 45; ' +
        ' Get-CimInstance SoftwareLicensingProduct -Filter "Name like \'Windows%\'" ' +
        '   | where { $_.PartialProductKey } | select Description, LicenseStatus'
    )

    try:
        shell = ShellHandler(control_ipv4_addr, user, password, verbose=verbose)
        stdout, stderr, exit_status = shell.execute_powershell(cmd)
    except paramiko.ssh_exception.AuthenticationException:
        print("Could not connect with credentials to register windows, already domain-joined?")
        return {}

    return {
        "node_details": obj,
        "stdout": stdout,
        "stderr": stderr,
        "exit_status": exit_status,
        "game_rename": game_rename,
        "control_rename": control_rename
    }
