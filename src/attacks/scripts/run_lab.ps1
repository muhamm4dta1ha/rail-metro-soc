param([switch]$RoeApproved, [switch]$Campaign,
      [ValidateSet('A','B','C')][string[]]$Scenarios = @('A','B','C'),
      [ValidateSet('baseline','attack')][string[]]$Modes = @('baseline','attack'))
$ErrorActionPreference = 'Stop'
if (-not $RoeApproved) { throw 'Confirm all four RoE approvals before using -RoeApproved' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
Set-Location -LiteralPath $repo
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$relative = "lab/evidence/runs/M2-$stamp"
$folder = Join-Path $repo $relative
New-Item -ItemType Directory -Path $folder | Out-Null
$runner = "m2-client-$stamp".ToLower()
$normal = "m2-normal-$stamp".ToLower()
$capture = "m2-capture-$stamp".ToLower()
$normalCapture = "m2-normal-capture-$stamp".ToLower()
$created = @()
function Assert-Lab {
    $net = (docker network inspect rail-metro-soc_dmz_ops | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0 -or -not $net.Internal -or $net.IPAM.Config[0].Subnet -ne '10.60.20.0/24') {
        throw 'DMZ isolation verification failed'
    }
    $assets = @{'pis'='10.60.20.10'; 'station-plc'='10.60.20.22'; 'occ'='10.60.20.20'}
    $proof = @()
    foreach ($service in $assets.Keys) {
        $item = (docker inspect "rail-metro-soc-$service-1" | ConvertFrom-Json)[0]
        $networks = $item.NetworkSettings.Networks.PSObject.Properties
        if (-not $item.State.Running -or $networks.Count -ne 1 -or
            $item.Config.Labels.'com.docker.compose.project' -ne 'rail-metro-soc' -or
            $item.NetworkSettings.Networks.'rail-metro-soc_dmz_ops'.IPAddress -ne $assets[$service]) {
            throw "Unexpected state or network placement: $service"
        }
        $proof += @{service=$service; ip=$assets[$service]; image=$item.Image; running=$true}
    }
    @{checked_utc=[DateTime]::UtcNow.ToString('o'); internal=$true; subnet='10.60.20.0/24'; assets=$proof} |
        ConvertTo-Json -Depth 6 -Compress | Add-Content "$folder/preflight.jsonl" -Encoding utf8
}
function Docker-Checked([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker operation failed: $($Arguments[0])" }
}
try {
    Assert-Lab
    # Existing synthetic account, held in process memory only. Never print inspect's environment.
    $pis = (docker inspect rail-metro-soc-pis-1 | ConvertFrom-Json)[0]
    $users = ($pis.Config.Env | Where-Object { $_.StartsWith('PIS_USERS=') }) -replace '^PIS_USERS=', ''
    if (-not $users) { throw 'PIS has no synthetic account configured' }
    $account = ($users -split ',')[0] -split ':', 2
    if ($account.Count -ne 2) { throw 'PIS synthetic account format invalid' }
    $env:M2_PIS_USER = $account[0]
    $env:M2_PIS_PASSWORD = $account[1]
    $mounts = @('-v', "${repo}:/workspace:ro", '-v', "${repo}/lab:/workspace/lab",
                '-w', '/workspace', '-e', 'PYTHONPATH=/workspace/src/attacks:/workspace/src/common:/workspace/src/simulation',
                '-e', 'M2_PIS_USER', '-e', 'M2_PIS_PASSWORD')
    Docker-Checked (@('run','-d','--name',$runner,'--network','rail-metro-soc_dmz_ops','--ip','10.60.20.99') +
                    $mounts + @('rail-metro-soc-occ','python','-c','import time; time.sleep(3600)'))
    $created += $runner
    Docker-Checked (@('run','-d','--name',$normal,'--network','container:rail-metro-soc-occ-1') +
                    $mounts + @('rail-metro-soc-occ','python','-c','import time; time.sleep(3600)'))
    $created += $normal
    foreach ($pair in @(@($capture,$runner), @($normalCapture,$normal))) {
        Docker-Checked @('run','-d','--name',$pair[0],'--network',"container:$($pair[1])",
                         '--cap-add','NET_RAW','-v',"${folder}:/capture",'nicolaka/netshoot:latest','sleep','3600')
        $created += $pair[0]
    }
    foreach ($scenario in $Scenarios) {
        Assert-Lab
        # Verify actual runner namespace before each scenario; .99 is not an inventory device.
        Docker-Checked @('exec',$runner,'python','-c',
            'import socket; s=socket.socket(); s.bind(("10.60.20.99",0)); s.close()')
        # An engaged shared kill switch must abort all three before traffic starts.
        Docker-Checked @('exec',$runner,'python','-c',
            'import tempfile; from pathlib import Path; from railsoc_attacks.safety import LabScope, KillSwitchEngaged; from railsoc_attacks.scenario import RunContext; p=Path(tempfile.mktemp()); p.touch(); c=RunContext("check",LabScope(kill_switch_file=p),{},False); exec("try:\n c.guard(\"10.60.20.10\")\n raise AssertionError(\"kill failed\")\nexcept KillSwitchEngaged:\n print(\"kill switch verified\")"); p.unlink()')
        foreach ($mode in $Modes) {
            $client = if ($mode -eq 'baseline') { $normal } else { $runner }
            $cap = if ($mode -eq 'baseline') { $normalCapture } else { $capture }
            $pcap = "$scenario-$mode.pcap"
            $filter = if ($scenario -eq 'B') { 'tcp port 502 and host 10.60.20.22' } else { 'tcp src port 8080 and src host 10.60.20.10' }
            Docker-Checked @('exec','-d',$cap,'tcpdump','-U','-n','-i','eth0','-w',"/capture/$pcap",$filter)
            Start-Sleep -Milliseconds 500
            try {
                $argsBatch = @('exec',$client,'python','-m','railsoc_attacks.lab_batch',$scenario,'--out',$relative)
                if ($mode -eq 'baseline') { $argsBatch += '--baseline' }
                & docker @argsBatch 2>&1 | Tee-Object -FilePath "$folder/$scenario-$mode-single.txt"
                if ($LASTEXITCODE -ne 0) { throw "$scenario $mode individual observations did not match expectations; campaign stopped" }
                if ($Campaign) {
                    & docker @argsBatch --campaign 2>&1 | Tee-Object -FilePath "$folder/$scenario-$mode-campaign.txt"
                    if ($LASTEXITCODE -ne 0) { throw "$scenario $mode campaign failed" }
                }
            } finally {
                & docker exec $cap pkill -INT tcpdump
                Start-Sleep -Milliseconds 500
            }
            Docker-Checked @('exec',$cap,'tcpdump','-nn','-r',"/capture/$pcap",'-c','3')
        }
    }
    Write-Output "Evidence session: $relative"
} finally {
    foreach ($name in ($created | Select-Object -Last 4)) { & docker stop --time 3 $name | Out-Null }
    foreach ($name in $created) { & docker rm $name | Out-Null }
    Remove-Item Env:M2_PIS_USER -ErrorAction SilentlyContinue
    Remove-Item Env:M2_PIS_PASSWORD -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $folder -File -Recurse | Where-Object { $_.Name -ne 'SESSION_SHA256SUMS.txt' } |
        ForEach-Object { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.FullName.Substring($folder.Length+1))" } |
        Set-Content "$folder/SESSION_SHA256SUMS.txt" -Encoding utf8
}

