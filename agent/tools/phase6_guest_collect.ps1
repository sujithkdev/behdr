param([string]$OutputRoot = 'C:\BehEDRLab\phase6')
$ErrorActionPreference = 'Stop'
# Run inside the disposable VMware Windows guest, with Sysmon already configured.
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Model -notmatch 'VMware') { throw 'Run this script inside the VMware lab guest.' }
$channel = 'Microsoft-Windows-Sysmon/Operational'
$initial = Get-WinEvent -LogName $channel -MaxEvents 1
if (-not $initial) { throw 'Sysmon channel is empty or unavailable. Configure Sysmon before collecting.' }
$runId = [guid]::NewGuid().ToString('N')
$runDir = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$started = [DateTime]::UtcNow
$scenarios = @()
$commands = @(
    @{name='command-version'; image="$env:WINDIR\System32\cmd.exe"; arguments='/d /c ver'},
    @{name='shadow-list'; image="$env:WINDIR\System32\vssadmin.exe"; arguments='list shadows'},
    @{name='boot-enumeration'; image="$env:WINDIR\System32\bcdedit.exe"; arguments='/enum'}
)
foreach ($entry in $commands) {
    $begin = [DateTime]::UtcNow
    $proc = Start-Process -FilePath $entry.image -ArgumentList $entry.arguments -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runDir ($entry.name+'.stdout.txt')) -RedirectStandardError (Join-Path $runDir ($entry.name+'.stderr.txt'))
    $scenarios += [ordered]@{name=$entry.name; label='benign'; pid=$proc.Id; image=$entry.image; arguments=$entry.arguments; started=$begin.ToString('o'); ended=[DateTime]::UtcNow.ToString('o'); exit_code=$proc.ExitCode}
}
Start-Sleep -Seconds 5
$last = Get-WinEvent -LogName $channel -MaxEvents 1
if ($last.RecordId -le $initial.RecordId) { throw 'No new Sysmon evidence: check process-create collection.' }
$xpath = "*[System[(EventRecordID > $($initial.RecordId)) and (EventRecordID <= $($last.RecordId))]]"
$events = @(Get-WinEvent -LogName $channel -FilterXPath $xpath -Oldest)
$xmlPath = Join-Path $runDir 'sysmon.xml'
$xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>'
[IO.File]::WriteAllText($xmlPath, $xml, (New-Object Text.UTF8Encoding($false)))
$scenarios | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runDir 'scenarios.json') -Encoding UTF8
$files = @('sysmon.xml','scenarios.json')
$hashes = @{}
foreach ($name in $files) { $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $runDir $name) -Algorithm SHA256).Hash.ToLowerInvariant() }
$manifest = [ordered]@{format='behedr-phase6-guest-v1'; run_id=$runId; evidence='live-benign-smoke'; host=$env:COMPUTERNAME; model=$machine.Model; os=(Get-CimInstance Win32_OperatingSystem).Caption; started=$started.ToString('o'); ended=[DateTime]::UtcNow.ToString('o'); first_record=$initial.RecordId; last_record=$last.RecordId; event_count=$events.Count; sha256=$hashes; limitations=@('Read-only benign smoke only; no malware efficacy measurement','Nonzero command exit codes are inconclusive','No installer, browser, build, backup or attack calibration in this bundle')}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runDir 'manifest.json') -Encoding UTF8
Write-Output "Evidence saved: $runDir"
Write-Output 'Review command lines for private data before sharing the bundle. No automatic upload was performed.'
