import role_domains
from shell_handler import ShellHandler

verbose = False


def setup_iis(
        iis_node,
        control_ipv4_addr,
        game_ipv4_addr,
        password,
        subca_node,
        leader_details,
        cloud_config,
        enterprise,
        enterprise_built
):

    name = iis_node["name"]
    subCA = subca_node["name"]
    domain = iis_node["domain"]
    enterprise_url = cloud_config['enterprise_url']

    fqdn = f"{name}.{domain}.{enterprise_url}"
    fqdn_domain_name = f"{domain}.{enterprise_url}"
    caConfig = f"{subCA}.{domain}.{enterprise_url}\\{domain}-SubCA"

    leader_admin_password = leader_details['admin_pass']
    game_leader_addrs = leader_details['game_addr']
    roles = iis_node['roles']
    iswindows = len(list(filter(lambda role: 'windows' == role, roles))) == 1

    if not iswindows:
        raise RuntimeError("Cannot install IIS on non-Windows systems")

    join_domain_results = role_domains.join_domain_windows(
        name,
        leader_admin_password,
        control_ipv4_addr,
        game_ipv4_addr,
        str(game_leader_addrs).replace("[", "").replace("]", "").replace("'", "\""),
        fqdn_domain_name,
        domain,
        password
    )
    print(f"  Installing IIS for node {name}")

    # NOTE: Added Invoke-ProcWithTimeoutAndRetry and switched all certreq calls to use it.
    # This mitigates intermittent hangs observed on `certreq.exe -accept`.
    setup_iis_cmd = f"""
# setup-iis-https.ps1
#
# Sets up IIS, requests an AD CS-signed HTTPS certificate,
# binds it to the default website, and serves a basic HTML page.

    function Ensure-Admin {{
        if (-not ([bool](New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {{
            Write-Error "This script must be run as Administrator."
            exit 1
        }}
    }}

    function Ensure-DomainJoin {{
        $cs = Get-WmiObject Win32_ComputerSystem
        if (-not $cs.PartOfDomain) {{
            Write-Error "This machine is not joined to a domain."
            exit 1
        }}
    }}

    function Ensure-Certreq {{
        if (-not (Get-Command certreq -ErrorAction SilentlyContinue)) {{
            Write-Error "certreq.exe not found. Make sure this is a full Windows system."
            exit 1
        }}
    }}

    function Ensure-CAAvailable ($caConfig) {{
        $caCheck = certutil -config "$caConfig" -ping 2>&1
        if ($LASTEXITCODE -ne 0) {{
            Write-Error "Could not contact the CA at $caConfig."
            $caCheck | Write-Host
            exit 1
        }}
    }}

    function Ensure-IIS {{
        if (-not (Get-WindowsFeature -Name Web-Server).Installed) {{
            Write-Host "Installing IIS Web-Server..."
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools
        }}
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {{
            Write-Error "WebAdministration PowerShell module is missing."
            exit 1
        }}
    }}

    function Create-TestPage {{
        $sitePath = "C:\\inetpub\\wwwroot"
        New-Item -ItemType Directory -Path $sitePath -Force | Out-Null
        $indexPath = Join-Path $sitePath "index.html"
@"
    <!DOCTYPE html>
    <html>
    <head>
        <title>It works!</title>
    </head>
    <body>
        <h1>HTTPS is working!</h1>
        <p>This site is secured with a certificate from Active Directory Certificate Services.</p>
    </body>
    </html>
"@ | Set-Content $indexPath -Encoding UTF8
    }}

    # Runs a process with timeout and retry. Kills on timeout.
    function Invoke-ProcWithTimeoutAndRetry {{
        param(
            [Parameter(Mandatory=$true)] [string] $FilePath,
            [Parameter(Mandatory=$true)] [string] $Arguments,
            [int] $TimeoutSeconds = 90,
            [int] $MaxRetries = 3,
            [int] $BackoffSeconds = 5
        )

        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {{
            Write-Host "[Invoke-Proc] Starting: $FilePath $Arguments (attempt $attempt of $MaxRetries)"

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $FilePath
            $psi.Arguments = $Arguments
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi

            [void]$proc.Start()

            if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {{
                Write-Warning "[Invoke-Proc] Timeout after $TimeoutSeconds s. Killing hung process (Id=$($proc.Id))."
                try {{ if ($PSVersionTable.PSEdition -eq 'Core') {{ $proc.Kill($true) }} else {{ try {{ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }} catch {{ }} & "$env:SystemRoot\\\System32\\taskkill.exe" /PID $($proc.Id) /T /F | Out-Null }} }} catch {{ Write-Warning "[Invoke-Proc] Kill failed: $($_)" }}
                Start-Sleep -Seconds $BackoffSeconds
                continue
            }}

            $stdout = $proc.StandardOutput.ReadToEnd()
            $stderr = $proc.StandardError.ReadToEnd()
            $exit = $proc.ExitCode

            if ($exit -eq 0) {{
                if ($stdout) {{ Write-Host "[Invoke-Proc][stdout]:`n$stdout" }}
                if ($stderr) {{ Write-Host "[Invoke-Proc][stderr]:`n$stderr" }}
                return 0
            }} else {{
                Write-Warning "[Invoke-Proc] ExitCode=$exit. Retrying in $BackoffSeconds s..."
                if ($stdout) {{ Write-Warning "[Invoke-Proc][stdout]:`n$stdout" }}
                if ($stderr) {{ Write-Warning "[Invoke-Proc][stderr]:`n$stderr" }}
                Start-Sleep -Seconds $BackoffSeconds
            }}
        }}

        Write-Error "[Invoke-Proc] Failed after $MaxRetries attempts: $FilePath $Arguments"
        return 1
    }}

    function Request-And-Bind-Cert ($fqdn, $caConfig, $siteName)
    {{
        $infPath = "C:\\tmp\\webserver.inf"
        $reqPath = "C:\\tmp\\webserver.req"
        $cerPath = "C:\\tmp\\webserver.cer"
        $rspPath = "C:\\tmp\\webserver.rsp"
        New-Item -ItemType Directory -Path (Split-Path $infPath) -Force | Out-Null

        # Always regenerate .inf and .req files
        $infContent = @"
[NewRequest]
Subject = "CN=$fqdn"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate = WebServer
"@
        $infContent | Set-Content -Path $infPath -Encoding ASCII

        # Delete any old request and cert files
        Remove-Item -Force -ErrorAction SilentlyContinue $reqPath, $cerPath, $rspPath

        # Create request
        $rc = Invoke-ProcWithTimeoutAndRetry -FilePath "C:\\Windows\\System32\\certreq.exe" -Arguments "-new `"$infPath`" `"$reqPath`"" -TimeoutSeconds 60 -MaxRetries 3 -BackoffSeconds 5
        if ($rc -ne 0) {{ throw "certreq -new failed ($rc)" }}

        # Submit request
        $rc = Invoke-ProcWithTimeoutAndRetry -FilePath "C:\\Windows\\System32\\certreq.exe" -Arguments "-submit -config `"$caConfig`" `"$reqPath`" `"$cerPath`"" -TimeoutSeconds 120 -MaxRetries 3 -BackoffSeconds 5
        if ($rc -ne 0) {{ throw "certreq -submit failed ($rc)" }}

        # Accept certificate (this was observed to hang intermittently; now guarded)
        $rc = Invoke-ProcWithTimeoutAndRetry -FilePath "C:\\Windows\\System32\\certreq.exe" -Arguments "-accept -machine -f `"$cerPath`"" -TimeoutSeconds 120 -MaxRetries 4 -BackoffSeconds 8
        if ($rc -ne 0) {{ throw "certreq -accept failed ($rc)" }}

        # Get the most recent matching cert
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object {{ $_.Subject -eq "CN=$fqdn" }} |
            Sort-Object NotBefore -Descending |
            Select-Object -First 1

        if (-not $cert)
        {{
            Write-Error "Failed to find installed certificate for $fqdn"
            exit 1
        }}

        # Configure IIS HTTPS binding if not present
        Import-Module WebAdministration

        $bindingExists = Get-WebBinding -Name $siteName -Protocol "https" -ErrorAction SilentlyContinue
        if (-not $bindingExists)
        {{
            New-WebBinding -Name $siteName -Protocol "https" -Port 443 -IPAddress "*" | Out-Null
        }}

        Push-Location IIS:\SslBindings
        $sslBinding = Get-Item "0.0.0.0!443" -ErrorAction SilentlyContinue

        if (-not $sslBinding -or $sslBinding.Thumbprint -ne $cert.Thumbprint)
        {{
            # Rebind if binding missing or thumbprint mismatched
            if ($sslBinding) {{ Remove-Item "0.0.0.0!443" -Force }}
            New-Item "0.0.0.0!443" -Thumbprint $cert.Thumbprint -SSLFlags 0 | Out-Null
        }}
        Pop-Location

        Write-Host "IIS configured with HTTPS using new AD CS certificate for $fqdn"
    }}



# === Main Script ===
    {role_domains.gpupdate_str}

    $fqdn = "{fqdn}"
    $siteName = "Default Web Site"
    $caConfig = "{caConfig}"

    Ensure-Admin
    Ensure-DomainJoin
    Ensure-Certreq
    Ensure-CAAvailable $caConfig
    Ensure-IIS
    Create-TestPage
    Request-And-Bind-Cert $fqdn $caConfig $siteName
    """

    iis_shell = ShellHandler(control_ipv4_addr, domain + '\\' + 'administrator', leader_admin_password)
    install_out, install_err, install_status = iis_shell.execute_powershell_multiline(
        setup_iis_cmd, filename="install-iis.ps1", verbose=verbose)

    print("  Successfully installed IIS")

    verify_cmd = f"""
$hostname = "{name}.{domain}.{enterprise_url}"
$tcpClient = New-Object System.Net.Sockets.TcpClient($hostname, 443)
$sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, ({{$true}}))

$sslStream.AuthenticateAsClient($hostname)
$cert = $sslStream.RemoteCertificate
$cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert

Write-Output "Subject: $($cert2.Subject)"
Write-Output "Issuer: $($cert2.Issuer)"
Write-Output "Thumbprint: $($cert2.Thumbprint)"
"""

    verify_out, verify_err, verify_status = iis_shell.execute_powershell_multiline(
        verify_cmd, filename="verify-iis.ps1", verbose=verbose)

    if f"Issuer: CN={domain}-SubCA, DC={domain}" not in str(verify_out + verify_err):
        print("install_iis_out:" + str(install_out))
        print("install_iis_err:" + str(install_err))
        print("verify_iis_out:" + str(verify_out))
        print("verify_iis_err:" + str(verify_err))
        errstr = f'Cannot verify certificate after IIS install on node {name}.'
        raise RuntimeError(errstr)

    return {
        "install-iis": {
            "join_domain_results": join_domain_results,
            "install_iis": {
                "install_cmd": setup_iis_cmd,
                "stdout": install_out,
                "stderr": install_err,
                "exit_status": install_status
            },
            "verify_iis": {
                "verify_cmd": verify_cmd,
                "stdout": verify_out,
                "stderr": verify_err,
                "exit_status": verify_status
            }
        }
    }
