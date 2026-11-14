#include <windows.h>
#include <shellapi.h>
#include <fstream>
#include <sstream>
#include <string>

// Control ID for an Activation button
#ifndef IDC_ACTIVATION_BTN
#define IDC_ACTIVATION_BTN 3013
#endif

bool RunActivationAction(HWND hwndParent) {
    // 1. Get the system temporary directory path
    wchar_t tempDir[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempDir) == 0) {
        MessageBoxW(hwndParent, L"Failed to resolve temp directory.", L"Activation Error", MB_OK | MB_ICONERROR);
        return false;
    }

    std::wstring scriptPath = std::wstring(tempDir) + L"mas_activation.ps1";

    // 2. Embed your exact PowerShell script inside a C++ raw string literal
    std::string rawScript = R"PS_SCRIPT(
if (-not $args) {
    Write-Host
    Write-Host 'Need help? Check our homepage: ' -NoNewline
    Write-Host 'https://massgrave.dev' -ForegroundColor Green
    Write-Host
}

& {
    $psv = (Get-Host).Version.Major
    $troubleshoot = 'https://massgrave.dev/troubleshoot'

    if ($ExecutionContext.SessionState.LanguageMode.value__ -ne 0) {
        $ExecutionContext.SessionState.LanguageMode
        Write-Host "PowerShell is not running in Full Language Mode."
        Write-Host "Help - https://massgrave.dev/fix_powershell" -ForegroundColor White -BackgroundColor Blue
        return
    }

    try {
        [void][System.AppDomain]::CurrentDomain.GetAssemblies(); [void][System.Math]::Sqrt(144)
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Powershell failed to load .NET command."
        Write-Host "Help - https://massgrave.dev/in-place_repair_upgrade" -ForegroundColor White -BackgroundColor Blue
        return
    }

    function Check3rdAV {
        $cmd = if ($psv -ge 3) { 'Get-CimInstance' } else { 'Get-WmiObject' }
        $avList = & $cmd -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object { $_.displayName -notlike '*windows*' } | Select-Object -ExpandProperty displayName

        if ($avList) {
            Write-Host '3rd party Antivirus might be blocking the script - ' -ForegroundColor White -BackgroundColor Blue -NoNewline
            Write-Host " $($avList -join ' ,')" -ForegroundColor DarkRed -BackgroundColor White
        }
    }

    function CheckFile {
        param ([string]$FilePath)
        if (-not (Test-Path $FilePath)) {
            Check3rdAV
            Write-Host "Failed to create MAS file in temp folder, aborting!"
            Write-Host "Help - $troubleshoot" -ForegroundColor White -BackgroundColor Blue
            throw
        }
    }

    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $URLs = @(
        'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/6cfd6f455ffb4983ce567231d800f08c44c39f00/MAS/All-In-One-Version-KL/MAS_AIO.cmd',
        'https://dev.azure.com/massgrave/Microsoft-Activation-Scripts/_apis/git/repositories/Microsoft-Activation-Scripts/items?path=/MAS/All-In-One-Version-KL/MAS_AIO.cmd&versionType=Commit&version=6cfd6f455ffb4983ce567231d800f08c44c39f00',
        'https://git.activated.win/Microsoft-Activation-Scripts/plain/MAS/All-In-One-Version-KL/MAS_AIO.cmd?id=6cfd6f455ffb4983ce567231d800f08c44c39f00'
    )
    Write-Progress -Activity "Downloading..." -Status "Please wait"
    $errors = @()
    foreach ($URL in $URLs | Sort-Object { Get-Random }) {
        try {
            if ($psv -ge 3) {
                $response = Invoke-RestMethod $URL
            }
            else {
                $w = New-Object Net.WebClient
                $response = $w.DownloadString($URL)
            }
            break
        }
        catch {
            $errors += $_
        }
    }
    Write-Progress -Activity "Downloading..." -Status "Done" -Completed

    if (-not $response) {
        Check3rdAV
        foreach ($err in $errors) {
            Write-Host "Error: $($err.Exception.Message)" -ForegroundColor Red
        }
        Write-Host "Failed to retrieve MAS from any of the available repositories, aborting!"
        Write-Host "Check if antivirus or firewall is blocking the connection."
        Write-Host "Help - $troubleshoot" -ForegroundColor White -BackgroundColor Blue
        return
    }

    # Verify script integrity
    $releaseHash = 'FDB7D70AE8A9577C5C6B0B2947ED93E664AC4E2C7A58BBF3DB9ABE9D2F6B9F01'
    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.StreamWriter $stream
    $writer.Write($response)
    $writer.Flush()
    $stream.Position = 0
    $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) -replace '-'
    if ($hash -ne $releaseHash) {
        Write-Warning "Hash ($hash) mismatch, aborting!`nReport this issue at $troubleshoot"
        $response = $null
        return
    }

    # Check for AutoRun registry which may create issues with CMD
    $paths = "HKCU:\SOFTWARE\Microsoft\Command Processor", "HKLM:\SOFTWARE\Microsoft\Command Processor"
    foreach ($path in $paths) { 
        if (Get-ItemProperty -Path $path -Name "Autorun" -ErrorAction SilentlyContinue) { 
            Write-Warning "Autorun registry found, CMD may crash! `nManually copy-paste the below command to fix...`nRemove-ItemProperty -Path '$path' -Name 'Autorun'"
        } 
    }

    $rand = [Guid]::NewGuid().Guid
    $isAdmin = [bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')
    $FilePath = if ($isAdmin) { "$env:SystemRoot\Temp\MAS_$rand.cmd" } else { "$env:USERPROFILE\AppData\Local\Temp\MAS_$rand.cmd" }
    Set-Content -Path $FilePath -Value "@::: $rand `r`n$response"
    CheckFile $FilePath

    $env:ComSpec = "$env:SystemRoot\system32\cmd.exe"
    $chkcmd = & $env:ComSpec /c "echo CMD is working"
    if ($chkcmd -notcontains "CMD is working") {
        Write-Warning "cmd.exe is not working.`nReport this issue at $troubleshoot"
    }

    if ($psv -lt 3) {
        if (Test-Path "$env:SystemRoot\Sysnative") {
            Write-Warning "Command is running with x86 Powershell, run it with x64 Powershell instead..."
            return
        }
        $p = Start-Process -FilePath $env:ComSpec -ArgumentList "/c """"$FilePath"" -el -qedit $args""" -Verb RunAs -PassThru
        $p.WaitForExit()
    }
    else {
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c """"$FilePath"" -el $args""" -Wait -Verb RunAs
    }	
    
    CheckFile $FilePath
    Remove-Item -Path $FilePath
} @args
)PS_SCRIPT";

    // 3. Write the script content to the temporary file on disk
    std::ofstream outFile(scriptPath, std::ios::out | std::ios::binary);
    if (!outFile) {
        MessageBoxW(hwndParent, L"Failed to write temporary script file.", L"Activation Error", MB_OK | MB_ICONERROR);
        return false;
    }
    outFile.write(rawScript.data(), rawScript.size());
    outFile.close();

    // 4. Construct parameters to run PowerShell silently using the temp file
    std::wstring parameters = L"-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + L"\"";

    // 5. Execute PowerShell via ShellExecuteW
    HINSTANCE result = ShellExecuteW(
        hwndParent,
        L"open",
        L"powershell.exe",
        parameters.c_str(),
        nullptr,
        SW_HIDE
    );

    const INT_PTR code = reinterpret_cast<INT_PTR>(result);
    if (code <= 32) {
        MessageBoxW(hwndParent, L"Failed to launch PowerShell.", L"Activation Error", MB_OK | MB_ICONERROR);
        return false;
    }

    return true;
}

bool HandleActivationCommand(HWND hwndParent, UINT commandId, UINT notificationCode) {
    if (commandId != IDC_ACTIVATION_BTN) {
        return false;
    }

    if (notificationCode != BN_CLICKED && notificationCode != 0) {
        return false;
    }

    RunActivationAction(hwndParent);
    return true;
}