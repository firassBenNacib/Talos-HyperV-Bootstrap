# SPDX-License-Identifier: GPL-3.0-ONLY
# Portions from "New-TalosVM" by nebula-it (functions: New-TalosVM, Get-NextVMNumber)
# Modifications © 2025 Firas Ben Nacib
#
#
#
#
#
#
#
#
#
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Position = 0)]
  [ValidateSet('create','bootstrap','kubeconfig','merge','clean','start','stop','list','help','unmerge','disk')]
  [string] $Command,

  [switch] $CreateVMs,
  [switch] $Bootstrap,
  [switch] $KubeconfigOnly,
  [switch] $MergeContexts,
  [switch] $Clean,
  [switch] $Purge,
  [switch] $RemoveISO,
  [switch] $Help,
  [switch] $StartVMs,
  [switch] $StopVMs,
  [switch] $List,
  [switch] $Unmerge,
  [switch] $Disk,

  [Alias('F')] [switch] $Force,
  [Alias('A')] [switch] $All,

  [int] $ControlPlaneCount = 1,
  [int] $WorkerCount       = 1,
  [ValidateRange(1,64)] [int] $ServerCPUs = 2,
  [ValidateRange(1,64)] [int] $WorkerCPUs = 1,
  [ValidateRange(0,32)] [int] $DefaultPrefix = 24,
  [int] $NtpSettleSeconds = 20,

  [ValidateNotNullOrEmpty()]
  [string] $SwitchName = "talos",
  [ValidateNotNullOrEmpty()]
  [string] $Dest = "C:\Virtual Machines\Talos VMs",
  [ValidatePattern('^\d+(?:[KMGT]B?|B)$')] [string] $ServerMem = '2G',
  [ValidatePattern('^\d+(?:[KMGT]B?|B)$')] [string] $WorkerMem = '1G',
  [string] $TalosISO = "$PSScriptRoot\metal-amd64.iso",
  [string] $TalosVersion,
  [string] $InstallDisk = '/dev/sda',
  [string] $Name,
  [string] $Gateway,
  [string] $DNS,
  [switch] $KeepIso,
  [switch] $NoConsole,

  [ValidateRange(1,4094)]
  [Nullable[int]] $VLAN,

  [ValidatePattern('^\d+(?:[KMGT]B?|B)$')] [string] $ServerDisk = '20G',
  [ValidatePattern('^\d+(?:[KMGT]B?|B)$')] [string] $WorkerDisk = '20G',

  [switch] $ShowDisk,

  [Alias('ResizeOSDisk')] [ValidatePattern('^\d+(?:[KMGT]B?|B)$')] [string] $ResizeDisk,
  [ValidatePattern('^\d+(?:[KMGT]B?|B)$')] [string] $AddDisk,

  [switch] $ControlPlanesOnly,
  [switch] $WorkersOnly,
  [string[]] $Node,

  [string[]] $Cluster
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

function Get-UsageText {
@"

Usage: .\Talos.ps1 <Command> [options]

  Commands
    create        Create VMs
    bootstrap     Configure nodes and fetch kubeconfig
    kubeconfig    Activate kubeconfig for a cluster or merged set
    merge         Merge kubeconfigs
    unmerge       Remove a merged kubeconfig set
    clean         Remove VMs and artifacts
    start         Start VMs
    stop          Stop VMs
    list          List clusters and VM states
    disk          Manage disks
    help          Show this help

  Global options
    -Cluster                      Target cluster
    -All, -A                      Apply to all clusters where applicable
    -Force, -F                    Force/overwrite where supported
    -SwitchName <vSwitch>         Hyper-V external vSwitch (default: talos)
    -Dest <path>                  VM root path (default: C:\Virtual Machines\Talos VMs)
    -TalosISO <path>              Path to Talos ISO (default: .\metal-amd64.iso)
    -TalosVersion <v>             Talos version to download if ISO missing
    -InstallDisk </dev/sd..>      Target install disk inside VM (default: /dev/sda)
    -DefaultPrefix <n>            Default CIDR prefix when omitted (default: /24)
    -VLAN <id>                    VLAN ID for VM NICs
    -ShowDisk                     When listing, include disk usage details
    -NoConsole                    Don’t auto-open VM consoles during create/bootstrap

  create options
    -ControlPlaneCount <n>        Number of control-plane VMs 
    -WorkerCount <n>              Number of worker VMs
    -ServerCPUs <n>               vCPU per control-plane
    -WorkerCPUs <n>               vCPU per worker
    -ServerMem <size>             Memory per control-plane 
    -WorkerMem <size>             Memory per worker 
    -ServerDisk <size>            OS disk per control-plane 
    -WorkerDisk <size>            OS disk per worker 
    -VLAN <id>                    VLAN for created VMs
    -Bootstrap                    Immediately run bootstrap after create
    -NoConsole                    Don’t open consoles after VM creation

  bootstrap options
    -Cluster <name>               Target cluster
    -Gateway <IPv4>               Default gateway to use
    -DNS <IPv4>                   DNS server to use
    -NtpSettleSeconds <n>         Wait after network switch 
    -KeepIso                      Keep ISO attached after bootstrap
    -NoConsole                    Don’t open consoles during bootstrap

  kubeconfig options
    -Cluster <name>               Target cluster or merged set to activate

  merge options
    -Cluster <name[,name...]>     Clusters and/or merged sets to merge
    -All                          Merge all available clusters
    -Name <friendly>              Name for the merged set directory

  unmerge options
    -Name <friendly>              Remove a specific merged set
    -All                          Remove all merged sets

  clean options
    -Cluster <name[,name...]>     Target cluster
    -All                          Clean all clusters
    -Purge                        Delete cluster artifacts in .\clusters
    -RemoveISO                    Remove downloaded ISO from script folder

  start/stop options
    -Cluster <name[,name...]>     Target cluster
    -All                          Apply to all clusters

  list options
    -Cluster <name[,name...]>     Filter to cluster
    -ShowDisk                     Show OS/data disk usage

  disk options
    -Cluster <name>               Target cluster
    -ResizeDisk <size>            Resize OS disk of target nodes
    -AddDisk <size>               Attach an extra data disk to target nodes
    -ControlPlanesOnly            Limit to control-plane nodes
    -WorkersOnly                  Limit to worker nodes
    -Node <vm[,vm...]>            Limit to specific VM names

"@
}


switch ( $Command ) {
  'create'     { $CreateVMs      = $true }
  'bootstrap'  { $Bootstrap      = $true }
  'kubeconfig' { $KubeconfigOnly = $true }
  'merge'      { $MergeContexts  = $true }
  'clean'      { $Clean          = $true }
  'start'      { $StartVMs       = $true }
  'stop'       { $StopVMs        = $true }
  'list'       { $List           = $true }
  'help'       { $Help           = $true }
  'unmerge'    { $Unmerge        = $true }
  'disk'       { $Disk           = $true }
}

if ( $Help -or ( $PSBoundParameters.Count -eq 0 -and -not $PSCmdlet.MyInvocation.UnboundArguments ) ) {
  Get-UsageText | Write-Host
  return
}

function Add-ExtraNamesToCluster ( [switch] $FirstOnly ) {
  $extras = @()
  if ( $PSCmdlet.MyInvocation.UnboundArguments ) {
    foreach ( $arg in $PSCmdlet.MyInvocation.UnboundArguments ) {
      if ( $arg -is [string] ) {
        $t = $arg.Trim()
        if ( $t -and $t -notmatch '^-') { $extras += $t }
      }
    }
  }
  if ( $extras.Count -gt 0 ) {
    if ( $FirstOnly ) { $extras = @( $extras[0] ) }
    if ( $null -eq $Cluster -or $Cluster.Count -eq 0 ) { $Cluster = @() }
    $script:Cluster += $extras
  }
}

if ( $StartVMs -or $StopVMs -or $Clean -or $Disk ) { Add-ExtraNamesToCluster }
if ( $MergeContexts ) { Add-ExtraNamesToCluster }
if ( $CreateVMs ) { if ( -not $PSBoundParameters.ContainsKey('Cluster') ) { Add-ExtraNamesToCluster -FirstOnly } }
if ( $KubeconfigOnly ) { if ( -not $PSBoundParameters.ContainsKey('Cluster') ) { Add-ExtraNamesToCluster -FirstOnly } }

function Test-AdminPrivilege {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = [Security.Principal.WindowsPrincipal]::new( $id )
  if ( -not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) ) {
    Write-Warning "Run in an elevated PowerShell."
  }
}

function Set-TextUtf8 ( [string] $Path, $Value ) {
  if ( $Value -is [System.Array] ) {
    $Text = [string]::Join([Environment]::NewLine, [string[]] $Value)
  } else {
    $Text = [string] $Value
  }
  if ( $PSVersionTable.PSVersion.Major -ge 6 ) {
    Set-Content -Path $Path -Value $Text -Encoding utf8NoBOM -Force
  } else {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    [System.IO.File]::WriteAllBytes($Path, $bytes)
  }
}

function ConvertTo-Bytes ( [string] $s ) {
  $s = $s.Trim().ToUpper()
  if ( $s -notmatch '^(\d+)([KMGT]B?|B)?$' ) { throw "Invalid size '$s'." }
  $n = [int64] $matches[1]
  $u = if ( $matches[2] ) { $matches[2] } else { 'B' }
  switch ( $u ) {
    'B'  { $n }
    'K'  { $n * 1KB }
    'KB' { $n * 1KB }
    'M'  { $n * 1MB }
    'MB' { $n * 1MB }
    'G'  { $n * 1GB }
    'GB' { $n * 1GB }
    'T'  { $n * 1TB }
    'TB' { $n * 1TB }
  }
}

function Enable-FeatureIfNeeded ( [string] $name ) {
  $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
  if ( $f -and $f.State -ne 'Enabled' ) {
    Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart | Out-Null
  }
}

function Invoke-DownloadIfMissing ( [string] $Path, [string] $Url, [string] $What ) {
  if ( Test-Path $Path ) { return $Path }
  Write-Host "Downloading $What ..." -ForegroundColor Cyan
  Invoke-WebRequest -Uri $Url -OutFile $Path
  Unblock-File $Path
  return $Path
}

function Get-TalosISO ( [string] $Path, [string] $Version ) {
  function Get-LatestStableTalosVersion {
    try {
      $headers = @{ 'User-Agent'='Talos.ps1'; 'Accept'='application/vnd.github+json' }

      $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/siderolabs/talos/releases/latest' -Headers $headers -ErrorAction Stop
      if ($latest -and -not $latest.prerelease -and -not $latest.draft -and $latest.tag_name) {
        return ($latest.tag_name.Trim()).TrimStart('v')
      }
    } catch { }

    try {
      $rels = Invoke-RestMethod -Uri 'https://api.github.com/repos/siderolabs/talos/releases?per_page=30' -Headers $headers -ErrorAction Stop
      $stable = $rels | Where-Object { -not $_.draft -and -not $_.prerelease } | Select-Object -First 1
      if ($stable -and $stable.tag_name) {
        return ($stable.tag_name.Trim()).TrimStart('v')
      }
    } catch { }

    return $null
  }

  $resolvedVersion = $null
  if ($Version) {
    $resolvedVersion = ($Version.Trim()).TrimStart('v')
  } else {
    $resolvedVersion = Get-LatestStableTalosVersion
    if (-not $resolvedVersion) {
      try {
        $talosctlPath = (Get-Command 'talosctl' -ErrorAction Stop).Source
        $verOut = & $talosctlPath version --client --short 2>$null
        if ($LASTEXITCODE -eq 0 -and $verOut) { $resolvedVersion = ($verOut.Trim()).TrimStart('v') }
      } catch { }
    }
    if (-not $resolvedVersion) { $resolvedVersion = '1.11.2' }
  }

  $arch = 'amd64'
  $url  = "https://github.com/siderolabs/talos/releases/download/v$resolvedVersion/metal-$arch.iso"
  Invoke-DownloadIfMissing -Path $Path -Url $url -What "metal-$arch.iso (v$resolvedVersion)" | Out-Null
}


function Get-VMGuid ( [string] $VMName ) { ( Get-VM -Name $VMName -ErrorAction Stop ).Id.ToString() }

function Test-VMConsoleOpen ( [string] $VMName ) {
  try { $guid = Get-VMGuid $VMName } catch { return $false }
  $escVM   = [regex]::Escape($VMName)
  $escGuid = [regex]::Escape($guid)
  $procs = Get-CimInstance Win32_Process -Filter "Name='vmconnect.exe'" -ErrorAction SilentlyContinue
  if ( $procs ) {
    $n = "(?i)\blocalhost\b\s+$escVM(\s|$)"
    $g = "(?i)\b-G\s+$escGuid(\s|$)"
    if ( $procs | Where-Object { $_.CommandLine -and ( $_.CommandLine -match $n -or $_.CommandLine -match $g ) } ) { return $true }
  }
  $gp = Get-Process -Name vmconnect -ErrorAction SilentlyContinue
  if ( $gp | Where-Object { try { $_.MainWindowTitle -match "(?i)\b$escVM\b.*Virtual Machine Connection" } catch { $false } } ) { return $true }
  return $false
}

function Start-VMIfNeeded ( [string] $VMName ) {
  $vm = Get-VM -Name $VMName -ErrorAction Stop
  if ( $vm.State -ne 'Running' ) { Start-VM -Name $VMName | Out-Null }
}

function Connect-VMConsole ( [string] $VMName ) {
  Start-VMIfNeeded $VMName
  if ( Test-VMConsoleOpen $VMName ) { return }
  $vmc = Join-Path $env:windir 'System32\vmconnect.exe'
  if ( Test-Path $vmc ) {
    try { Start-Process -FilePath $vmc -ArgumentList @('localhost', $VMName) | Out-Null; return } catch { }
    try { Start-Process -FilePath $vmc -ArgumentList @('localhost','-G', ( Get-VMGuid $VMName )) | Out-Null } catch { }
  }
}

function Disconnect-VMConsole ( [string] $VMName ) {
  try {
    $guid   = Get-VMGuid $VMName
    $escVM  = [regex]::Escape($VMName)
    $escGid = [regex]::Escape($guid)
    Get-CimInstance Win32_Process -Filter "Name='vmconnect.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and ( $_.CommandLine -match "(?i)$escVM" -or $_.CommandLine -match "(?i)$escGid" ) } |
      ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch { } }
  } catch { }
}

function Get-ClustersRoot {
  $root = Join-Path $PSScriptRoot 'clusters'
  if ( -not ( Test-Path $root ) ) { New-Item -ItemType Directory -Force -Path $root | Out-Null }
  $root
}

function New-RandomClusterName { 'cluster-' + ( [guid]::NewGuid().ToString('N').Substring(0,4) ) }

function Get-ExistingClusters {
  $root = Get-ClustersRoot
  @( Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
     Where-Object { $_.Name -notlike '_*' -and ( Test-Path ( Join-Path $_.FullName 'talosconfig' ) ) } |
     Select-Object -ExpandProperty Name )
}

function Get-ClustersFromVMs {
  $names = @()
  $all = @()
  $tmp = Get-VM -Name "*-cp*" -ErrorAction SilentlyContinue; if ( $tmp ) { $all += $tmp }
  $tmp = Get-VM -Name "*-w*"  -ErrorAction SilentlyContinue; if ( $tmp ) { $all += $tmp }
  foreach ( $v in ( $all | Select-Object -ExpandProperty Name | Sort-Object -Unique ) ) {
    if ( $v -match '^(.*?)-(?:cp|w)\d+$' ) { $names += $matches[1] }
  }
  @( $names | Sort-Object -Unique )
}

function Get-AllClusterNames {
  $a = @( Get-ExistingClusters )
  $b = @( Get-ClustersFromVMs )
  @( $a + $b ) | Sort-Object -Unique
}

function Select-FromList ( [string] $Action, [string[]] $List ) {
  if ( -not $List -or $List.Count -eq 0 ) { throw "No clusters found." }
  Write-Host "Available clusters:" -ForegroundColor Cyan
  for ( $i = 0; $i -lt $List.Count; $i++ ) { Write-Host "[$($i+1)] $($List[$i])" }
  $sel = Read-Host ( "Select cluster to {0} 1-{1}" -f $Action, $List.Count )
  if ( $sel -match '^\d+$' ) { $idx = [int] $sel; if ( $idx -ge 1 -and $idx -le $List.Count ) { return $List[$idx-1] } }
  throw "Invalid selection."
}

function Resolve-Cluster ( [string] $Action, [bool] $ConsiderParam ) {
  if ( $ConsiderParam -and $Cluster -and $Cluster.Count -ge 1 ) {
    $list = Get-AllClusterNames
    if ( $list -and ( $list -contains $Cluster[0] ) ) { return $Cluster[0] }
    Write-Host ( "Cluster '{0}' not found." -f $Cluster[0] ) -ForegroundColor Yellow
  }
  return ( Select-FromList $Action ( Get-AllClusterNames ) )
}

function Confirm-ClusterName ( [string] $name, [switch] $ThrowOnExists, [switch] $AllowReuse ) {
  $root = Get-ClustersRoot
  $dest = Join-Path $Dest $name
  $exists = ( Test-Path ( Join-Path $root $name ) ) -or ( Test-Path $dest ) -or ( $null -ne ( Get-VM -Name "$name-*" -ErrorAction SilentlyContinue ) )
  if ( $exists -and $ThrowOnExists -and -not $AllowReuse ) { throw "Cluster '$name' already exists." }
  $name
}

function Get-ClusterPaths ( [string] $name ) {
  $root = Get-ClustersRoot
  $dir = Join-Path $root $name
  @{
    Dir           = $dir
    TalosConfig   = ( Join-Path $dir 'talosconfig' )
    Kubeconfig    = ( Join-Path $dir 'kubeconfig' )
    ControlPlane  = ( Join-Path $dir 'controlplane.yaml' )
    Worker        = ( Join-Path $dir 'worker.yaml' )
    BootstrapMark = ( Join-Path $dir '.bootstrapped' )
    EndpointFile  = ( Join-Path $dir '.endpoint' )
  }
}

function Get-ClusterVMs ( [string] $ClusterName ) {
  $cps = Get-VM -Name "$ClusterName-cp*" -ErrorAction SilentlyContinue | Sort-Object Name
  $wks = Get-VM -Name "$ClusterName-w*"  -ErrorAction SilentlyContinue | Sort-Object Name
  @{ ControlPlanes = $cps; Workers = $wks }
}

function Select-MultipleClusters ( [string[]] $List, [string] $Prompt ) {
  if ( -not $List -or $List.Count -eq 0 ) { throw "No clusters found." }
  Write-Host "Available clusters:" -ForegroundColor Cyan
  for ( $i = 0; $i -lt $List.Count; $i++ ) { Write-Host "[$($i+1)] $($List[$i])" }
  $inp = Read-Host ( "$Prompt (comma-separated indexes)" )
  $raw = $inp -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  if ( $raw.Count -eq 0 ) { throw "Nothing selected." }
  $sel = @()
  foreach ( $r in $raw ) {
    if ( $r -notmatch '^\d+$' ) { throw "Bad selection '$r'." }
    $n = [int] $r
    if ( $n -lt 1 -or $n -gt $List.Count ) { throw "Index out of range: $n" }
    $sel += $List[$n-1]
  }
  ,( @( $sel | Sort-Object -Unique ) )
}

function Resolve-Targets {
  param(
    [string]  $Action,
    [switch]  $All,
    [string[]]$Cluster
  )
  $pool = @( Get-AllClusterNames )

  if ( $All ) { return ,$pool }
  if ( $PSBoundParameters.ContainsKey('Cluster') -and $Cluster ) { return ,(@($Cluster | Sort-Object -Unique)) }
  if ( -not $pool -or $pool.Count -eq 0 ) { return @() }

  return ( Select-MultipleClusters $pool "Select clusters to $Action" )
}


function Remove-KubeEntries ( [string] $ClusterName ) {
  $kubectlCmd = Get-Command 'kubectl' -ErrorAction SilentlyContinue
  if ( -not $kubectlCmd ) { return }
  $kubectl = $kubectlCmd.Source
  $ctx = "admin@$ClusterName"
  try { & $kubectl config delete-context $ctx 2>$null | Out-Null } catch { }
  try { & $kubectl config delete-cluster $ClusterName 2>$null | Out-Null } catch { }
}

function Get-MergedStateFile { Join-Path ( Get-ClustersRoot ) '.merged-set.txt' }
function Get-MergedNameFile  { Join-Path ( Get-ClustersRoot ) '.merged-name.txt' }

function Get-MergedSet {
  $f = Get-MergedStateFile
  if ( Test-Path $f ) {
    @( Get-Content -Raw $f -ErrorAction SilentlyContinue ).Split("`n") |
      ForEach-Object { $_.Trim() } | Where-Object { $_ }
  } else { @() }
}

function Save-MergedSet {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param( [string[]] $names )
  $seen = @{}
  $ordered = @()
  foreach ( $n in $names ) {
    $t = $n.Trim()
    if ( $t -and -not $seen.ContainsKey($t) ) { $seen[$t] = $true; $ordered += $t }
  }
  $f = Get-MergedStateFile
  if ( $ordered.Count -gt 0 ) {
    Set-TextUtf8 -Path $f -Value ( $ordered -join "`n" )
  } else {
    if ( $PSCmdlet.ShouldProcess($f, "Remove merged set file") ) {
      Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    }
  }
  ,$ordered
}

function Get-MergedFriendlyName ( [string[]] $names ) {
  ( $names | ForEach-Object { $_.Trim() } | Where-Object { $_ } ) -join '-'
}

function ConvertTo-SafeName ( [string] $n ) {
  if ( [string]::IsNullOrWhiteSpace($n) ) { return $null }
  $t = $n.Trim() -replace '[^\w\-]','-'
  while ( $t -match '\-\-' ) { $t = $t -replace '\-\-','-' }
  $t.Trim('-')
}

function Get-BinOrThrow ( [Parameter(Mandatory)] [string] $Name, [string] $Why ) {
  $p = ( Get-Command $Name -ErrorAction SilentlyContinue ).Source
  if ( -not $p ) { throw "Required CLI '$Name' not found in PATH. $Why" }
  $p
}

function Update-MergedKubeconfig ( [string[]] $names, [string] $SetName ) {
  $kubectl = Get-BinOrThrow -Name 'kubectl' -Why "'merge' needs kubectl."
  $files = foreach ($c in $names) {
    $p = (Get-ClusterPaths $c).Kubeconfig
    if (Test-Path $p) { $p }
  }
  if (-not $files -or $files.Count -le 0) { throw "No kubeconfig files to merge." }

  $oldKC = $env:KUBECONFIG
  $env:KUBECONFIG = ($files -join ';')
  $lines = & $kubectl config view --merge --flatten 2>$null
  $env:KUBECONFIG = $oldKC
  if ($null -eq $lines) { throw "kubectl failed to merge kubeconfigs." }

  $merged = if ($lines -is [System.Array]) { [string]::Join("`r`n", [string[]]$lines) } else { [string]$lines }

  $friendly = if (-not [string]::IsNullOrWhiteSpace($SetName)) {
    $t = ConvertTo-SafeName $SetName
    if ($t) { $t } else { Get-MergedFriendlyName $names }
  } else {
    Get-MergedFriendlyName $names
  }

  $root   = Get-ClustersRoot
  $outDir = Join-Path $root $friendly
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
  $outCfg = Join-Path $outDir 'kubeconfig'
  Set-TextUtf8 -Path $outCfg -Value $merged
  Set-TextUtf8 -Path (Get-MergedNameFile) -Value $friendly
  $outCfg
}


function Get-MergedDirs {
  $root = Get-ClustersRoot
  @( Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
     Where-Object {
       $_.Name -notlike '_*' -and
       ( Test-Path ( Join-Path $_.FullName 'kubeconfig' ) ) -and
       -not ( Test-Path ( Join-Path $_.FullName 'talosconfig' ) )
     } | Select-Object -ExpandProperty Name )
}

function Remove-MergedSetByName {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param( [string] $Name )
  $root = Get-ClustersRoot
  $dir  = Join-Path $root $Name
  if ( Test-Path $dir ) {
    if ( $PSCmdlet.ShouldProcess($dir, "Remove merged kubeconfig directory") ) {
      Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  $nameFile = Get-MergedNameFile
  if ( Test-Path $nameFile ) {
    $cur = ( Get-Content -Raw $nameFile ).Trim()
    if ( $cur -eq $Name ) {
      if ( $PSCmdlet.ShouldProcess($nameFile, "Remove merged name file") ) {
        Remove-Item -LiteralPath $nameFile -Force -ErrorAction SilentlyContinue
      }
      Save-MergedSet @() | Out-Null
    }
  }
  if ( $env:KUBECONFIG -and ( $env:KUBECONFIG -like ( Join-Path $dir '*' ) ) ) {
    $env:KUBECONFIG = $null
  }
  $curSet = Get-MergedSet | Where-Object { $_ -ne $Name }
  Save-MergedSet $curSet | Out-Null
  Write-Host ( "Removed merged set '{0}'." -f $Name ) -ForegroundColor Green
}

function Remove-FromMergedSet {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param( [string] $name )
  $current = Get-MergedSet
  $newSet = @( $current | Where-Object { $_ -ne $name } )
  $newSet = Save-MergedSet $newSet
  if ( $newSet.Count -gt 0 ) {
    try { [void] ( Update-MergedKubeconfig $newSet $null ) } catch { }
  } else {
    $nameFile = Get-MergedNameFile
    if ( Test-Path $nameFile ) {
      $oldName = ( Get-Content -Raw $nameFile ).Trim()
      if ( $oldName ) {
        $oldDir = Join-Path ( Get-ClustersRoot ) $oldName
        if ( Test-Path $oldDir ) {
          if ( $PSCmdlet.ShouldProcess($oldDir, "Remove empty merged set directory") ) {
            Remove-Item -LiteralPath $oldDir -Recurse -Force -ErrorAction SilentlyContinue
          }
        }
      }
      if ( $PSCmdlet.ShouldProcess($nameFile, "Remove merged name file") ) {
        Remove-Item -LiteralPath $nameFile -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Clear-TalosArtifacts {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param( [switch] $RemoveISO )
  $root = Get-ClustersRoot
  if ( Test-Path $root ) {
    try {
      if ( $PSCmdlet.ShouldProcess($root, "Purge cluster artifacts") ) {
        Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
          Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        Write-Host ( "Purged artifacts under {0}" -f $root ) -ForegroundColor Green
      }
    } catch { }
  }
  if ( $RemoveISO ) {
    $iso = Join-Path $PSScriptRoot 'metal-amd64.iso'
    try {
      if ( Test-Path $iso ) {
        if ( $PSCmdlet.ShouldProcess($iso, "Remove downloaded ISO") ) {
          Remove-Item -LiteralPath $iso -Force -ErrorAction SilentlyContinue
          Write-Host ( "Removed {0}" -f $iso ) -ForegroundColor Green
        }
      }
    } catch { }
  }
}

function Remove-ClusterEnvironment {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [string] $ClusterName,
    [string] $DestBase,
    [switch] $Purge,
    [switch] $RemoveISO
  )
  $clusterDir  = ( Get-ClusterPaths $ClusterName ).Dir
  $destCluster = Join-Path $DestBase $ClusterName
  Write-Host ( "Removing VMs for cluster '{0}'..." -f $ClusterName ) -ForegroundColor Cyan
  $vms = @()
  foreach ( $pat in @("$ClusterName-cp*","$ClusterName-w*","$ClusterName-*") ) {
    $tmp = Get-VM -Name $pat -ErrorAction SilentlyContinue
    if ( $tmp ) { $vms += $tmp }
  }
  $vms = $vms | Sort-Object -Property Name -Unique
  if ( -not $vms -or $vms.Count -eq 0 ) {
    Write-Host "  No VMs found for this cluster." -ForegroundColor DarkGray
  } else {
    foreach ( $v in $vms ) {
      try {
        if ( $PSCmdlet.ShouldProcess($v.Name, "Disconnect console and Stop-VM -TurnOff -Force") ) {
          Disconnect-VMConsole $v.Name
          Stop-VM -Name $v.Name -TurnOff -Force -ErrorAction SilentlyContinue
        }
      } catch { }
    }
    foreach ( $v in $vms ) {
      try {
        if ( $PSCmdlet.ShouldProcess($v.Name, "Remove-VM -Force") ) {
          Remove-VM -Name $v.Name -Force -ErrorAction SilentlyContinue
        }
      } catch { }
    }
  }
  if ( Test-Path $destCluster ) {
    if ( $PSCmdlet.ShouldProcess($destCluster, "Remove VM files") ) {
      try { Remove-Item -LiteralPath $destCluster -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
  }
  if ( $Purge ) {
    if ( Test-Path $clusterDir ) {
      if ( $PSCmdlet.ShouldProcess($clusterDir, "Purge cluster config/artifacts") ) {
        try { Remove-Item -LiteralPath $clusterDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
      }
    }
  }
  Write-Host ( "Cleanup complete for '{0}'." -f $ClusterName ) -ForegroundColor Green
  if ( $Purge -and $RemoveISO ) {
    $iso = Join-Path $PSScriptRoot 'metal-amd64.iso'
    try {
      if ( Test-Path $iso ) {
        if ( $PSCmdlet.ShouldProcess($iso, "Remove downloaded ISO") ) {
          Remove-Item -LiteralPath $iso -Force -ErrorAction SilentlyContinue
        }
      }
    } catch { }
  }
}

Test-AdminPrivilege

if ( $Unmerge ) {
  if ( $All ) {
    $m = @( Get-MergedDirs )
    if ( -not $m -or $m.Count -eq 0 ) { Write-Host "No merged sets found." -ForegroundColor Yellow; return }
    foreach ( $x in $m ) { Remove-MergedSetByName $x }
    Save-MergedSet @() | Out-Null
    return
  } else {
    if ( $Name ) {
      $nm = ConvertTo-SafeName $Name
      if ( -not $nm ) { Write-Host "Invalid -Name." -ForegroundColor Yellow; return }
      $dirs = @( Get-MergedDirs )
      if ( -not ( $dirs -contains $nm ) ) { Write-Host "Merged set '$nm' not found." -ForegroundColor Yellow; return }
      Remove-MergedSetByName $nm
      return
    }
    $m = @( Get-MergedDirs )
    if ( -not $m -or $m.Count -eq 0 ) { Write-Host "No merged sets found." -ForegroundColor Yellow; return }
    $target = Select-FromList 'unmerge' $m
    Remove-MergedSetByName $target
    return
  }
}

if ( $Clean ) {
  if ( $All ) {
    $allNames   = @( Get-AllClusterNames )
    $mergedDirs = @( Get-MergedDirs )

    if ( -not $allNames -and -not $mergedDirs ) {
      Write-Host "Nothing found." -ForegroundColor Yellow
      if ( $Purge ) { Clear-TalosArtifacts -RemoveISO:$RemoveISO }
      return
    }

    foreach ( $name in $allNames ) {
      if ( $PSCmdlet.ShouldProcess($name, "Remove cluster environment") ) {
        Remove-ClusterEnvironment -ClusterName $name -DestBase $Dest -Purge:$Purge -RemoveISO:$RemoveISO
        Remove-KubeEntries -ClusterName $name
        Remove-FromMergedSet -name $name
      }
    }

    foreach ( $m in $mergedDirs ) { Remove-MergedSetByName $m }

    if ( $Purge ) { Clear-TalosArtifacts -RemoveISO:$RemoveISO }
    return
  }

  $existing   = @( Get-AllClusterNames )
  $mergedDirs = @( Get-MergedDirs )
  if ( -not $PSBoundParameters.ContainsKey('Cluster') -and ( $existing.Count -eq 0 ) -and ( $mergedDirs.Count -eq 0 ) ) {
    Write-Host "Nothing found." -ForegroundColor Yellow
    if ( $Purge ) { Clear-TalosArtifacts -RemoveISO:$RemoveISO }
    return
  }
  if ( $PSBoundParameters.ContainsKey('Cluster') -and $Cluster -and $Cluster.Count -ge 1 ) {
    $targets = @( $Cluster | Sort-Object -Unique )
  } else {
    $targets = Select-MultipleClusters ( @( $existing + $mergedDirs ) | Sort-Object -Unique ) "Select clusters to clean"
  }
  foreach ( $target in $targets ) {
    if ( $mergedDirs -contains $target ) {
      Remove-MergedSetByName $target
      continue
    }
    if ( $PSCmdlet.ShouldProcess($target, "Remove cluster environment") ) {
      Remove-ClusterEnvironment -ClusterName $target -DestBase $Dest -Purge:$Purge -RemoveISO:$RemoveISO
      Remove-KubeEntries -ClusterName $target
      Remove-FromMergedSet -name $target
    }
  }
  if ( $Purge -and -not ( Get-AllClusterNames ) ) { Clear-TalosArtifacts -RemoveISO:$RemoveISO }
  return
}

Enable-FeatureIfNeeded -name Microsoft-Hyper-V-All
Enable-FeatureIfNeeded -name Microsoft-Hyper-V-Tools-All
Enable-FeatureIfNeeded -name Microsoft-Hyper-V-Management-Clients

try {
  $sw = Get-VMSwitch -Name $SwitchName -ErrorAction Stop
  if ( $sw.SwitchType -ne 'External' ) { throw ( "Switch '{0}' is type '{1}'. Use an External vSwitch." -f $SwitchName, $sw.SwitchType ) }
} catch {
  throw ( "Hyper-V switch '{0}' not found." -f $SwitchName )
}

function Format-GB ( [Int64] $bytes ) { ( "{0:N1}G" -f ( $bytes / 1GB ) ) }

function Get-VMVhdInfo ( [string] $VMName ) {
  $infos = @()
  $drives = Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue
  foreach ( $d in ( $drives | Where-Object { $_.Path } ) ) {
    if ( Test-Path $d.Path ) {
      try {
        $v = Get-VHD -Path $d.Path -ErrorAction Stop
        $infos += [pscustomobject]@{
          Path = $d.Path; Size = $v.Size; FileSize = $v.FileSize; MinimumSize = $v.MinimumSize;
          VhdFormat = $v.VhdFormat; VhdType = $v.VhdType
        }
      } catch { }
    }
  }
  ,$infos
}

function Get-PrimaryOsVhd ( [string] $VMName, $infos ) {
  if ( -not $infos -or $infos.Count -eq 0 ) { return $null }
  $exact = $infos | Where-Object { ( Split-Path -Leaf $_.Path ) -ieq "$VMName.vhdx" } | Select-Object -First 1
  if ( $exact ) { return $exact }
  return $infos[0]
}

function Merge-CheckpointsIfAny ( [string] $VMName ) {
  $snaps = @( Get-VMSnapshot -VMName $VMName -ErrorAction SilentlyContinue )
  if ( -not $snaps -or $snaps.Count -eq 0 ) { return }
  Write-Host ( "  ! Removing {0} checkpoint(s) for {1} before resizing..." -f $snaps.Count, $VMName ) -ForegroundColor Yellow
  Remove-VMSnapshot -VMName $VMName -Name * -Confirm:$false -ErrorAction SilentlyContinue
  $deadline = ( Get-Date ).AddMinutes(10)
  do {
    Start-Sleep -Seconds 3
    $still = @( Get-VMSnapshot -VMName $VMName -ErrorAction SilentlyContinue )
    $infos = Get-VMVhdInfo $VMName
    $os = Get-PrimaryOsVhd $VMName $infos
    $avhd = ( $os -and ( $os.VhdType -eq 'Differencing' -or $os.Path -like '*.avhdx' ) )
    $pending = ( $still.Count -gt 0 ) -or $avhd
  } while ( $pending -and ( Get-Date ) -lt $deadline )
  if ( $pending ) { throw ( "{0}: checkpoint merge did not complete in time." -f $VMName ) }
  Write-Host ( "  ✓ {0}: checkpoints merged" -f $VMName ) -ForegroundColor Green
}

function Add-DataDisk ( [string] $VMName, [Int64] $SizeBytes ) {
  $infos = Get-VMVhdInfo $VMName
  $os = Get-PrimaryOsVhd $VMName $infos
  if ( -not $os ) { throw "No VHD info for $VMName" }
  $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
  $wasRunning = $vm -and ( $vm.State -ne 'Off' )
  if ( $wasRunning ) {
    Write-Host ( "  ! Stopping {0} to attach data disk" -f $VMName ) -ForegroundColor Yellow
    Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue
  }
  $dir = Split-Path -Parent $os.Path
  $i = 1
  do {
    $newPath = Join-Path $dir ( "{0}-Data{1:00}.vhdx" -f $VMName, $i )
    $i++
  } while ( Test-Path $newPath )

  New-VHD -Path $newPath -SizeBytes $SizeBytes -ErrorAction Stop | Out-Null
  Add-VMHardDiskDrive -VMName $VMName -Path $newPath -ErrorAction Stop | Out-Null
  Write-Host ( "  + {0}: attached data disk {1} (max {2})" -f $VMName, ( Split-Path -Leaf $newPath ), ( Format-GB $SizeBytes ) ) -ForegroundColor Green
  if ( $wasRunning ) {
    try { Start-VM -Name $VMName | Out-Null } catch { }
  }
}

function Get-OsVhdPath ( [string] $VMName ) {
  $hdds = @( Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop )
  if ( -not $hdds ) { throw ( "{0}: no hard disks attached." -f $VMName ) }

  $exact = $hdds | Where-Object { $_.Path -and (Split-Path -Leaf $_.Path) -ieq "$VMName.vhdx" } | Select-Object -First 1
  if ($exact) { return $exact.Path }

  $scsi00 = $hdds | Where-Object { $_.ControllerType -eq 'SCSI' -and $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0 } | Select-Object -First 1
  if ($scsi00) { return $scsi00.Path }

  throw ( "{0}: OS VHD not found (no exact match or SCSI 0:0). Aborting to avoid touching the wrong disk." -f $VMName )
}


function Resize-OsVhd ( [string] $VMName, [Int64] $NewSizeBytes ) {

  Merge-CheckpointsIfAny $VMName


  $osPath = Get-OsVhdPath $VMName
  if ( -not $osPath ) { throw ( "{0}: OS VHD path not found." -f $VMName ) }

  $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
  $wasRunning = $vm -and ( $vm.State -ne 'Off' )
  if ( $wasRunning ) {
    Write-Host ( "  ! Stopping {0} to resize OS disk" -f $VMName ) -ForegroundColor Yellow
    Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue
  }

  $pre = Get-VHD -Path $osPath -ErrorAction Stop

  if ( $pre.VhdType -eq 'Differencing' ) {
    throw ( "{0}: OS disk is still a differencing disk ({1}). Ensure checkpoints are fully merged and try again." -f $VMName, $osPath )
  }

  if ( $NewSizeBytes -eq $pre.Size ) {
    Write-Host ( "  = {0}: OS disk already {1}" -f $VMName, ( Format-GB $pre.Size ) ) -ForegroundColor DarkGray
    if ( $wasRunning ) { try { Start-VM -Name $VMName | Out-Null } catch { } }
    return
  }

  if ( $NewSizeBytes -lt $pre.Size ) {
    if ( $pre.VhdFormat -ne 'VHDX' ) {
      throw ( "{0}: shrinking requires VHDX (current: {1})" -f $VMName, $pre.VhdFormat )
    }
    if ( $NewSizeBytes -lt $pre.MinimumSize ) {
      throw ( "{0}: requested {1} < minimum shrinkable size {2}" -f $VMName, ( Format-GB $NewSizeBytes ), ( Format-GB $pre.MinimumSize ) )
    }
  }

  Resize-VHD -Path $osPath -SizeBytes $NewSizeBytes -ErrorAction Stop

  $post = Get-VHD -Path $osPath -ErrorAction Stop
  $arrow = if ( $post.Size -gt $pre.Size ) { '↑' } elseif ( $post.Size -lt $pre.Size ) { '↓' } else { '=' }
  Write-Host ( "  {0} {1}: OS disk now {2}" -f $arrow, $VMName, ( Format-GB $post.Size ) ) -ForegroundColor Green

  if ( $wasRunning ) { try { Start-VM -Name $VMName | Out-Null } catch { } }
}


function Get-VhdChainUsage([string]$HeadPath) {
  $total=[int64]0; $virtual=[int64]0
  $p=$HeadPath
  while ($p) {
    try { $v = Get-VHD -Path $p -ErrorAction Stop } catch { break }
    $virtual = [int64]$v.Size
    $total  += [int64]$v.FileSize
    $p = $v.ParentPath
  }
  [pscustomobject]@{ TotalFileSize=$total; VirtualSize=$virtual }
}

function Write-VMStatus ( [object] $vm, [switch] $ShowDiskDetails ) {
  $name = $vm.Name; $state = $vm.State
  if ( -not $ShowDiskDetails ) { Write-Host ( "    {0,-22} {1}" -f $name, $state ); return }

  $infos = Get-VMVhdInfo $name
  $os = Get-PrimaryOsVhd $name $infos
  if ($os) {
    $chain = Get-VhdChainUsage $os.Path
    $pct = if ($chain.VirtualSize -gt 0) { [math]::Round(100.0 * ($chain.TotalFileSize / $chain.VirtualSize),1) } else { 0 }
    $dataCount = @($infos | Where-Object { $_.Path -ne $os.Path }).Count
    Write-Host ( "    {0,-22} {1}  OS:{2}/{3} (~{4}%)  Data:{5}" -f $name, $state, (Format-GB $chain.TotalFileSize), (Format-GB $chain.VirtualSize), $pct, $dataCount )
  } else {
    Write-Host ( "    {0,-22} {1}" -f $name, $state )
  }
}


if ( $List ) {
  $targets = @()
  if ( $PSBoundParameters.ContainsKey('Cluster') -and $Cluster -and $Cluster.Count -ge 1 ) {
    $targets = @( $Cluster | Sort-Object -Unique )
  } else {
    $targets = @( Get-AllClusterNames )
  }
  if ( -not $targets -or $targets.Count -eq 0 ) { Write-Host "No clusters found." -ForegroundColor Yellow; return }
  foreach ( $c in $targets ) {
    Write-Host ( "`nCluster: {0}" -f $c ) -ForegroundColor Cyan
    $vmset = Get-ClusterVMs $c
    if ( $vmset.ControlPlanes ) {
      Write-Host "  Control planes:" -ForegroundColor DarkCyan
      $vmset.ControlPlanes | ForEach-Object { Write-VMStatus $_ -ShowDiskDetails:$ShowDisk }
    } else { Write-Host "  Control planes: none" }
    if ( $vmset.Workers ) {
      Write-Host "  Workers:" -ForegroundColor DarkCyan
      $vmset.Workers | ForEach-Object { Write-VMStatus $_ -ShowDiskDetails:$ShowDisk }
    } else { Write-Host "  Workers: none" }
  }
  Write-Host ""
  return
}

function Set-ClusterVMState ( [string[]] $clusters, [ValidateSet('Start','Stop')] $Action ) {
  foreach ( $t in $clusters ) {
    $vms = Get-VM -Name "$t-*" -ErrorAction SilentlyContinue | Sort-Object Name
    if ( -not $vms ) { Write-Host ( "{0}: no VMs found." -f $t ) -ForegroundColor Yellow; continue }
    $changed = @(); $already = @()
    foreach ( $v in $vms ) {
      if ( $Action -eq 'Start' ) {
        if ( $v.State -ne 'Running' ) { Start-VM -Name $v.Name | Out-Null; $changed += $v.Name } else { $already += $v.Name }
      } else {
        if ( $v.State -ne 'Off' ) {
          try { Stop-VM -Name $v.Name -TurnOff -Force -ErrorAction SilentlyContinue; $changed += $v.Name } catch { }
        } else { $already += $v.Name }
      }
    }
    if ( $changed.Count -gt 0 ) {
      if ( $Action -eq 'Start' ) {
        Write-Host ( "{0}: started {1}" -f $t, ( $changed -join ', ' ) ) -ForegroundColor Green
      } else {
        Write-Host ( "{0}: stopped {1}" -f $t, ( $changed -join ', ' ) ) -ForegroundColor Green
      }
    }
    if ( $already.Count -gt 0 ) {
      if ( $Action -eq 'Start' ) {
        Write-Host ( "{0}: already running {1}" -f $t, ( $already -join ', ' ) ) -ForegroundColor DarkGray
      } else {
        Write-Host ( "{0}: already stopped {1}" -f $t, ( $already -join ', ' ) ) -ForegroundColor DarkGray
      }
    }
  }
}

if ( $StartVMs ) {
  $targets = Resolve-Targets -Action 'start' -All:$All -Cluster $Cluster
  if ( -not $targets -or $targets.Count -eq 0 ) { Write-Host "No clusters found." -ForegroundColor Yellow; return }
  Set-ClusterVMState -clusters $targets -Action Start
  return
}

if ( $StopVMs ) {
  $targets = Resolve-Targets -Action 'stop' -All:$All -Cluster $Cluster
  if ( -not $targets -or $targets.Count -eq 0 ) { Write-Host "No clusters found." -ForegroundColor Yellow; return }
  Set-ClusterVMState -clusters $targets -Action Stop
  return
}


[string[]] $CpVMs = @()
[string[]] $WVMs  = @()

function Get-NextVMNumber {
  param( $prefix )
  $existing = Get-VM -Name "$prefix*" -ErrorAction SilentlyContinue
  if ( $existing ) {
    $nums = foreach ( $v in $existing ) {
      if ( $v.Name -match ( [regex]::Escape($prefix) + '(\d+)$' ) ) { [int] $matches[1] }
    }
    $n = if ( $nums ) { ( $nums | Measure-Object -Maximum ).Maximum + 1 } else { 1 }
  } else { $n = 1 }
  return "$prefix" + $n.ToString('000')
}

function New-TalosVM {
  param(
    [Parameter(Mandatory)] [string] $VMNamePrefix,
    [Int64] $CPUCount = 2,
    [Int64] $StartupMemory = 4GB,
    [Parameter(Mandatory)] [string] $SwitchName,
    [ValidateRange(1,4094)]
    [Nullable[int]] $VLAN,
    [Int64] $VHDSize = 10GB,
    [Parameter(Mandatory)] [string] $TalosISOPath,
    [string] $VMDestinationBasePath = 'C:\Virtual Machines\Talos VMs',
    [Int64] $NumberOfVMs = 1
  )
  process {
    if ( $VHDSize -lt 3MB ) {
      throw ("Requested OS disk size {0} bytes is too small. Use a value like 20G or 30GB." -f $VHDSize)
    }

    $created = @()
    for ( $i = 1; $i -le $NumberOfVMs; $i++ ) {
      $VMName = Get-NextVMNumber $VMNamePrefix
      $VMPath = Join-Path $VMDestinationBasePath $VMName

      $vhddir  = Join-Path $VMPath 'Virtual Hard Disks'
      if (-not (Test-Path $vhddir)) {
        New-Item -ItemType Directory -Force -Path $vhddir | Out-Null
      }
      $vhdPath = Join-Path $vhddir "$VMName.vhdx"

      $props = @{
        Name               = $VMName
        MemoryStartupBytes = $StartupMemory
        Generation         = 2
        NewVHDPath         = $vhdPath
        Path               = $VMPath
        NewVHDSizeBytes    = $VHDSize
        SwitchName         = $SwitchName
      }
      New-VM @props -ErrorAction Stop | Out-Null
      
      Set-VM -Name $VMName -ProcessorCount $CPUCount -ErrorAction Stop
      Set-VMMemory -VMName $VMName -DynamicMemoryEnabled:$false -StartupBytes $StartupMemory -ErrorAction Stop
      Add-VMDvdDrive -VMName $VMName -ErrorAction Stop | Out-Null
      Set-VMDvdDrive -VMName $VMName -Path $TalosISOPath -ErrorAction Stop
      Set-VMFirmware -VMName $VMName -EnableSecureBoot Off -FirstBootDevice (Get-VMDvdDrive -VMName $VMName -ErrorAction Stop) -ErrorAction Stop

      if ($PSBoundParameters.ContainsKey('VLAN') -and $null -ne $VLAN) {
        Set-VMNetworkAdapterVlan -VMName $VMName -VlanId $VLAN -Access -ErrorAction Stop
      }

      try {
        Start-VM -Name $VMName | Out-Null
      } catch {
        Write-Warning ("{0}: created but not started ({1})" -f $VMName, $_.Exception.Message)
      }

      $created += $VMName
    }
    ,$created
  }
}


function Get-SelectableClusters {
  @( Get-AllClusterNames | Where-Object {
      $p = ( Get-ClusterPaths $_ ).Kubeconfig
      Test-Path $p
    } )
}

function Use-Kubeconfig ( [string] $Path, [string] $ClusterName ) {
  $env:KUBECONFIG = $Path
  $kubectl = (Get-Command 'kubectl' -ErrorAction SilentlyContinue).Source
  if ($kubectl) {
    try {
      & $kubectl config use-context ("admin@{0}" -f $ClusterName) --kubeconfig $Path 2>$null | Out-Null
    } catch {
      try {
        $ctx = (& $kubectl config get-contexts --kubeconfig $Path -o name 2>$null | Select-Object -First 1)
        if ($ctx) { & $kubectl config use-context $ctx --kubeconfig $Path 2>$null | Out-Null }
      } catch {}
    }
  }
  Write-Host ("Active kubeconfig: {0}" -f $ClusterName) -ForegroundColor Green
}


if ( $CreateVMs ) {
  $name = if ( $PSBoundParameters.ContainsKey('Cluster') -and $Cluster -and $Cluster.Count -ge 1 ) { $Cluster[0] } else { ( Read-Host "Enter cluster name blank for random" ) }
  if ( [string]::IsNullOrWhiteSpace($name) ) {
    $name = New-RandomClusterName
  } else {
    $name = $name.Trim() -replace '[^\w\-]','-'
    $name = Confirm-ClusterName $name -ThrowOnExists -AllowReuse:$Force
  }
  $ClusterName = $name
  $paths = Get-ClusterPaths $ClusterName
  if ( -not ( Test-Path $paths.Dir ) ) { New-Item -ItemType Directory -Force -Path $paths.Dir | Out-Null }
  Get-TalosISO -Path $TalosISO -Version $TalosVersion | Out-Null
  $srvMemB = ConvertTo-Bytes $ServerMem
  $wrkMemB = ConvertTo-Bytes $WorkerMem
  $serverDiskB = ConvertTo-Bytes $ServerDisk
  $workerDiskB = ConvertTo-Bytes $WorkerDisk
  $minOsVhdBytes = 3MB
  if ( $serverDiskB -lt $minOsVhdBytes ) { throw "ServerDisk '$ServerDisk' is too small. Use a size like 20G or 30GB." }
  if ( $workerDiskB -lt $minOsVhdBytes ) { throw "WorkerDisk '$WorkerDisk' is too small. Use a size like 20G or 30GB." }
  $basePath = ( Join-Path $Dest $ClusterName )
  $cpParams = @{
    VMNamePrefix            = "$ClusterName-cp"
    CPUCount                = $ServerCPUs
    StartupMemory           = $srvMemB
    SwitchName              = $SwitchName
    TalosISOPath            = $TalosISO
    NumberOfVMs             = $ControlPlaneCount
    VMDestinationBasePath   = $basePath
    VHDSize                 = $serverDiskB
  }
  if ( $PSBoundParameters.ContainsKey('VLAN') ) { $cpParams.VLAN = $VLAN }
  $wkParams = @{
    VMNamePrefix            = "$ClusterName-w"
    CPUCount                = $WorkerCPUs
    StartupMemory           = $wrkMemB
    SwitchName              = $SwitchName
    TalosISOPath            = $TalosISO
    NumberOfVMs             = $WorkerCount
    VMDestinationBasePath   = $basePath
    VHDSize                 = $workerDiskB
  }
  if ( $PSBoundParameters.ContainsKey('VLAN') ) { $wkParams.VLAN = $VLAN }
  try {
    $CpVMs = [string[]] ( New-TalosVM @cpParams )
    $WVMs  = [string[]] ( New-TalosVM @wkParams )
  } catch {
    Write-Host ( "Create failed: {0}`nRolling back partial cluster '{1}' ..." -f $_.Exception.Message, $ClusterName ) -ForegroundColor Yellow
    Remove-ClusterEnvironment -ClusterName $ClusterName -DestBase $Dest -Purge:$true
    throw
  }
  Write-Host ( "VMs ready in cluster '{0}': CP=[{1}], Workers=[{2}]" -f $ClusterName, ( $CpVMs -join ', ' ), ( $WVMs -join ', ' ) ) -ForegroundColor Green
  if ( -not $NoConsole ) { foreach ( $n in @( $CpVMs + $WVMs ) ) { Connect-VMConsole $n } }
  if ( -not $Bootstrap ) { Write-Host ( "Next: .\Talos.ps1 bootstrap -Cluster {0}" -f $ClusterName ) -ForegroundColor Yellow; return }
}

elseif ( $KubeconfigOnly ) {
  $clusters = @( Get-AllClusterNames )
  $merged   = @( Get-MergedDirs )
  $options  = @( $clusters + $merged ) | Sort-Object -Unique
  if ( -not $PSBoundParameters.ContainsKey('Cluster') -or -not $Cluster -or $Cluster.Count -lt 1 ) {
    if ( -not $options -or $options.Count -eq 0 ) { throw "No clusters or merged kubeconfigs found." }
    Write-Host "Available targets:" -ForegroundColor Cyan
    for ( $i = 0; $i -lt $options.Count; $i++ ) { Write-Host "[$($i+1)] $($options[$i])" }
    $sel = Read-Host ( "Select cluster/merged kubeconfig to activate 1-{0}" -f $options.Count )
    if ( $sel -match '^\d+$' ) {
      $idx = [int] $sel
      if ( $idx -ge 1 -and $idx -le $options.Count ) { $ClusterName = $options[$idx-1] } else { throw "Invalid selection." }
    } else {
      throw "Invalid selection."
    }
  } else {
    $ClusterName = $Cluster[0]
    if ( -not ( $options -contains $ClusterName ) ) { throw "Target '$ClusterName' not found." }
  }
  $paths = Get-ClusterPaths $ClusterName
  $talosConfPath = $paths.TalosConfig
  $kubeconfPath  = $paths.Kubeconfig
  $isMergedOnly = ( -not ( Test-Path $talosConfPath ) ) -and ( Test-Path $kubeconfPath )
  if ( $isMergedOnly ) {
    Use-Kubeconfig -Path $kubeconfPath -ClusterName $ClusterName
    return
  }
  if ( -not ( Test-Path $talosConfPath ) ) { throw "No talosconfig found for '$ClusterName'." }
  $env:TALOSCONFIG = $talosConfPath
  $endpoint = if ( Test-Path $paths.EndpointFile ) { ( Get-Content -Raw $paths.EndpointFile ).Trim() } else { $null }
  $talosctl = Get-BinOrThrow -Name 'talosctl' -Why ""
  & $talosctl --talosconfig $talosConfPath kubeconfig --force $paths.Dir 2>$null
  if ( $LASTEXITCODE -ne 0 -and $endpoint ) {
    & $talosctl --talosconfig $talosConfPath --nodes $endpoint kubeconfig --force $paths.Dir
  }
  if ( $LASTEXITCODE -ne 0 ) {
    $cp = Read-Host "Enter a reachable control-plane IP for '$ClusterName' or press Enter to abort"
    if ( [string]::IsNullOrWhiteSpace($cp) ) { throw "Unable to obtain kubeconfig automatically." }
    & $talosctl --talosconfig $talosConfPath --nodes $cp kubeconfig --force $paths.Dir
    if ( $LASTEXITCODE -eq 0 ) { Set-TextUtf8 -Path $paths.EndpointFile -Value $cp }
  }
  if ( $LASTEXITCODE -ne 0 ) { throw "kubeconfig fetch failed. Check that the control-plane is up and reachable." }
  if ( Test-Path $kubeconfPath ) {
    Use-Kubeconfig -Path $kubeconfPath -ClusterName $ClusterName
  }
  return
}
elseif ( $MergeContexts ) {
  $kubectlPath = Get-BinOrThrow -Name 'kubectl' -Why "'merge' needs kubectl."
  function Expand-MergedSet ( [string] $setName ) {
    $kc = ( Get-ClusterPaths $setName ).Kubeconfig
    $out = @()
    if ( Test-Path $kc ) {
      $ctxs = & $kubectlPath config get-contexts --kubeconfig $kc -o name 2>$null
      foreach ( $c in $ctxs ) { if ( $c -match 'admin@(.*)$' ) { $out += $matches[1] } }
    }
    if ( -not $out -or $out.Count -eq 0 ) { $out = $setName.Split('-') }
    ,( @( $out | Sort-Object -Unique ) )
  }
  [string[]] $set = @()
  $preferred = $null
  if ( $All ) {
    $withKc = Get-SelectableClusters
    if ( $withKc.Count -gt 0 ) { $set = Save-MergedSet $withKc; $preferred = $set[0] } else { throw "No kubeconfigs found to merge." }
  }
  elseif ( $PSBoundParameters.ContainsKey('Cluster') -and $Cluster -and $Cluster.Count -ge 1 ) {
    $expanded = @()
    $mergedDirs = @( Get-MergedDirs )
    foreach ( $n in $Cluster ) {
      if ( $mergedDirs -contains $n ) { $expanded += ( Expand-MergedSet $n ) } else { $expanded += $n }
    }
    $set = Save-MergedSet ( $expanded | Sort-Object -Unique )
    $preferred = $set[0]
  }
  else {
    $clusters = Get-SelectableClusters
    if ( -not $clusters -or $clusters.Count -eq 0 ) { throw "No kubeconfigs found to merge." }
    $mergedDirs = @( Get-MergedDirs )
    $items = @()
    $items += ( $clusters | ForEach-Object { [pscustomobject]@{ Name = $_; Kind = 'cluster' } } )
    $items += ( $mergedDirs | ForEach-Object { [pscustomobject]@{ Name = $_; Kind = 'merged' } } )
    Write-Host "Items available to merge:" -ForegroundColor Cyan
    for ( $i = 0; $i -lt $items.Count; $i++ ) {
      $tag = if ( $items[$i].Kind -eq 'cluster' ) { 'cluster' } else { 'merged set' }
      Write-Host ( "[{0}] {1} ({2})" -f ( $i + 1 ), $items[$i].Name, $tag )
    }
    $inp = Read-Host "Select items by index or name (comma-separated)"
    $raw = $inp -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ( $raw.Count -eq 0 ) { throw "Nothing selected." }
    $selClusters = @()
    foreach ( $r in $raw ) {
      if ( $r -match '^\d+$' ) {
        $idx = [int] $r; if ( $idx -lt 1 -or $idx -gt $items.Count ) { throw "Index out of range: $r" }
        $itm = $items[$idx-1]
        if ( $itm.Kind -eq 'merged' ) { $selClusters += ( Expand-MergedSet $itm.Name ) } else { $selClusters += $itm.Name }
      } else {
        $match = $items | Where-Object { $_.Name -eq $r }
        if ( -not $match ) { throw "Unknown selection '$r'." }
        if ( $match.Kind -eq 'merged' ) { $selClusters += ( Expand-MergedSet $match.Name ) } else { $selClusters += $match.Name }
      }
    }
    $set = Save-MergedSet ( $selClusters | Sort-Object -Unique )
    $preferred = $set[0]
  }
  $mergedFile = Update-MergedKubeconfig $set $Name
  $env:KUBECONFIG = $mergedFile
  try { & $kubectlPath config use-context ( "admin@{0}" -f $preferred ) 2>$null | Out-Null } catch { }
  $friendly = ( Split-Path -Leaf ( Split-Path -Parent $mergedFile ) )
  Write-Host ( "Merged set [{0}] -> {1}" -f ( $set -join ', ' ), $friendly ) -ForegroundColor Green
  Write-Host ( "Active kubeconfig: {0}" -f $friendly ) -ForegroundColor DarkGray
  return
}
elseif ( $Disk ) {
  if ( -not $PSBoundParameters.ContainsKey('Cluster') -or -not $Cluster -or $Cluster.Count -lt 1 ) {
    $ClusterName = Resolve-Cluster 'disk' $false
  } else {
    $ClusterName = $Cluster[0]
  }
  if ( -not $ResizeDisk -and -not $AddDisk ) { throw "Nothing to do. Use -ResizeDisk <size> and/or -AddDisk <size>." }
  $vmset = Get-ClusterVMs $ClusterName
  $targets = @()
  if ( $PSBoundParameters.ContainsKey('ControlPlanesOnly') -and $ControlPlanesOnly ) {
    if ( $vmset.ControlPlanes ) { $targets += ( $vmset.ControlPlanes | Select-Object -ExpandProperty Name ) }
  } elseif ( $PSBoundParameters.ContainsKey('WorkersOnly') -and $WorkersOnly ) {
    if ( $vmset.Workers ) { $targets += ( $vmset.Workers | Select-Object -ExpandProperty Name ) }
  } else {
    if ( $vmset.ControlPlanes ) { $targets += ( $vmset.ControlPlanes | Select-Object -ExpandProperty Name ) }
    if ( $vmset.Workers ) { $targets += ( $vmset.Workers | Select-Object -ExpandProperty Name ) }
  }
  if ( $PSBoundParameters.ContainsKey('Node') -and $Node ) {
    $targets = @( $targets | Where-Object { $Node -contains $_ } )
  }
  if ( -not $targets -or $targets.Count -eq 0 ) { throw "No target VMs found for cluster '$ClusterName'." }
  if ( $ResizeDisk ) {
    $newBytes = ConvertTo-Bytes $ResizeDisk
    foreach ( $v in $targets ) { Resize-OsVhd -VMName $v -NewSizeBytes $newBytes }
  }
  if ( $AddDisk ) {
    $sizeBytes = ConvertTo-Bytes $AddDisk
    foreach ( $v in $targets ) { Add-DataDisk -VMName $v -SizeBytes $sizeBytes }
  }
  Write-Host "Disk operations complete." -ForegroundColor Green
  return
}
else {
  $ClusterName = Resolve-Cluster 'bootstrap' ( $PSBoundParameters.ContainsKey('Cluster') )
  $CpVMs = @( Get-VM -Name "$ClusterName-cp*" -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -ExpandProperty Name )
  $WVMs  = @( Get-VM -Name "$ClusterName-w*"  -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -ExpandProperty Name )
  if ( -not $CpVMs -or $CpVMs.Count -eq 0 ) { throw ( "No control-plane VMs found for cluster '{0}'. Run: .\Talos.ps1 create" -f $ClusterName ) }
  if ( -not $WVMs ) { $WVMs = @() }
}

$paths = Get-ClusterPaths $ClusterName
if ( -not ( Test-Path $paths.Dir ) ) { New-Item -ItemType Directory -Force -Path $paths.Dir | Out-Null }
$TALOSCONF  = $paths.TalosConfig
$env:TALOSCONFIG = $TALOSCONF

$bootMark = $paths.BootstrapMark
$firstRun = -not ( Test-Path $bootMark )

[string[]] $SelCpVMs = $CpVMs
[string[]] $SelWVMs  = $WVMs

if ( ( -not $NoConsole ) -and ( $firstRun -or $Force ) ) {
  foreach ( $n in @( $CpVMs + $WVMs ) ) { Connect-VMConsole $n }
}

if ( -not $firstRun -and -not $Force ) {
  Write-Host "Cluster already bootstrapped. Skipping bootstrap." -ForegroundColor Yellow
  $talosctl = ( Get-Command 'talosctl' -ErrorAction SilentlyContinue ).Source
  if ( -not ( Test-Path $paths.Kubeconfig ) -and $talosctl ) {
    $endpoint = if ( Test-Path $paths.EndpointFile ) { ( Get-Content -Raw $paths.EndpointFile ).Trim() } else { $null }
    if ( $endpoint ) {
      & $talosctl --talosconfig $paths.TalosConfig --nodes $endpoint kubeconfig --force $paths.Dir
    }
  }
  return
}

function Test-IPv4([string]$s) {
  $obj = $null
  if (-not [System.Net.IPAddress]::TryParse($s, [ref]$obj)) { return $false }
  return ($obj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
}


function Split-CIDR ( [string] $cidr, [int] $defaultPrefix ) {
  if ( $cidr -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$' ) { throw ( "Invalid IP or CIDR: '{0}'" -f $cidr ) }
  $ip = $matches[1]
  if (-not (Test-IPv4 $ip)) { throw ("Invalid IPv4 address in CIDR: '{0}'" -f $cidr) }
  $prefix = if ( $matches[2] ) { [int] $matches[2] } else { [int] $defaultPrefix }
  if ( $prefix -lt 0 -or $prefix -gt 32 ) { throw ( "Invalid prefix '/{0}'" -f $prefix ) }
  @{ ip = $ip; prefix = $prefix }
}


function Get-MaskOctets ( [int] $prefix ) {
  $m = @( 0, 0, 0, 0 ); $full = [math]::Floor( $prefix / 8 ); $rem = $prefix % 8
  for ( $i = 0; $i -lt $full; $i++ ) { $m[$i] = 255 }
  if ( $rem -gt 0 ) { $m[$full] = ( ( 0xFF -shl ( 8 - $rem ) ) -band 0xFF ) }
  $m
}

function ConvertFrom-IPv4String ( [string] $ip ) { ( $ip.Split('.') | ForEach-Object { [int] $_ } ) }
function ConvertTo-IPv4String   ( [int[]] $o )   { "{0}.{1}.{2}.{3}" -f $o[0], $o[1], $o[2], $o[3] }

function Get-OctetBitwiseAnd ( [int[]] $a, [int[]] $b ) { $c = @( 0, 0, 0, 0 ); for ( $i = 0; $i -lt 4; $i++ ) { $c[$i] = ( $a[$i] -band $b[$i] ) }; $c }

function Get-NetworkBase ( [string] $cidr, [int] $defaultPrefix ) {
  $sp = Split-CIDR $cidr $defaultPrefix; $ipO = ConvertFrom-IPv4String $sp.ip; $msk = Get-MaskOctets $sp.prefix; $net = Get-OctetBitwiseAnd $ipO $msk; ConvertTo-IPv4String $net
}

function Get-NextIPv4 ( [string] $ip ) {
  $o = ConvertFrom-IPv4String $ip; for ( $i = 3; $i -ge 0 ) { if ( $o[$i] -lt 255 ) { $o[$i]++; break } else { $o[$i] = 0 } }; ConvertTo-IPv4String $o
}

function Get-GatewayBasePlusOne ( [string] $cidr, [int] $defaultPrefix ) {
  $sp = Split-CIDR $cidr $defaultPrefix
  if ( $sp.prefix -ge 31 ) { throw "Cannot auto-derive gateway for /31 or /32; pass -Gateway." }
  Get-NextIPv4 ( Get-NetworkBase $cidr $defaultPrefix )
}

function Get-IPv4Address ( [string] $s, [string] $label = 'IPv4' ) {
  if ( $s -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?\s*$' ) {
    throw ( "Invalid {0}: '{1}'" -f $label, $s )
  }
  $ip = $matches[1]
  if (-not (Test-IPv4 $ip)) { throw ( "Invalid {0}: '{1}'" -f $label, $s ) }
  $ip
}


if ( $PSBoundParameters.ContainsKey('Gateway') -and $Gateway ) { $Gateway = Get-IPv4Address $Gateway 'Gateway' }
if ( $PSBoundParameters.ContainsKey('DNS') -and $DNS ) { $DNS = Get-IPv4Address $DNS 'DNS' }

function Get-VMNicMacColon ( [string] $vm ) {
  $m = ( Get-VMNetworkAdapter -VMName $vm -ErrorAction Stop | Select-Object -First 1 -ExpandProperty MacAddress )
  if ( -not $m ) { throw ( "Couldn't read MAC for '{0}'" -f $vm ) }
  $m = $m -replace '[-:]',''; $m = $m.ToLower(); ( $m -replace '(.{2})(?!$)','$1:' )
}

function Wait-TcpPort ( [string] $Target, [int] $Port, [int] $TimeoutSec = 600 ) {
  $deadline = ( Get-Date ).AddSeconds( $TimeoutSec )
  while ( ( Get-Date ) -lt $deadline ) {
    try {
      $c = New-Object System.Net.Sockets.TcpClient; $iar = $c.BeginConnect( $Target, $Port, $null, $null )
      if ( $iar.AsyncWaitHandle.WaitOne( 1500, $false ) ) { $c.EndConnect( $iar ) | Out-Null; $c.Close(); return $true }
      $c.Close()
    } catch { }
    Start-Sleep -Seconds 2
  }
  return $false
}

function Get-NetPatch ( [string] $mac, [string] $cidr, [string] $gw, [string] $dns ) {
  $dir = Join-Path $PSScriptRoot 'templates'
  $tmplPath = Join-Path $dir 'static-net.tmpl.yaml'
  if ( -not ( Test-Path $tmplPath ) ) { throw ( "Template not found: {0}" -f $tmplPath ) }
  $t = Get-Content -Raw $tmplPath
  $t = $t.Replace('{{MAC}}',  $mac)
  $t = $t.Replace('{{CIDR}}', $cidr)
  $t = $t.Replace('{{GW}}',   $gw)
  $t = $t.Replace('{{DNS}}',  $dns)
  $t
}


function Read-NodeIPs ( [string[]] $VMs, [int] $DefaultPrefix, [string] $Gateway, [string] $DNS ) {
  $out = @()
  foreach ( $n in $VMs ) {
    $curIp = Get-IPv4Address ( Read-Host ( "Enter CURRENT IPv4 for {0}" -f $n ) )
    $st    = Read-Host ( "Enter STATIC IPv4 or IPv4/CIDR for {0}" -f $n )
    if ( [string]::IsNullOrWhiteSpace($st) ) {
      $cidr = "{0}/{1}" -f $curIp, $DefaultPrefix
      $ip   = $curIp
    } else {
      $sp = Split-CIDR $st $DefaultPrefix
      if ( $sp.prefix -ge 31 -and -not $Gateway ) { throw ( "Prefixes /31 and /32 require -Gateway for {0}" -f $n ) }
      $cidr = "{0}/{1}" -f $sp.ip, $sp.prefix
      $ip   = $sp.ip
    }
    $gw  = if ( $Gateway ) { $Gateway } else { Get-GatewayBasePlusOne $cidr $DefaultPrefix }
    $dns = if ( $DNS ) { $DNS } else { $gw }
    $mac = Get-VMNicMacColon $n
    $out += [pscustomobject]@{ Name = $n; Current = $curIp; CIDR = $cidr; IP = $ip; GW = $gw; DNS = $dns; MAC = $mac }
  }
  return ,$out
}

function Invoke-NodeConfig {
  [CmdletBinding()]
  param(
    [object[]] $nodes,
    [string] $YamlPath,
    [string] $TalosConf
  )
  $talosctl = Get-BinOrThrow -Name 'talosctl' -Why "needed for apply-config."
  foreach ( $n in $nodes ) {
    $patch = Get-NetPatch -mac $n.MAC -cidr $n.CIDR -gw $n.GW -dns $n.DNS
    $talosArgs = @('--talosconfig', $TalosConf, 'apply-config', '--insecure', '--nodes', $n.Current, '--file', $YamlPath, '--config-patch', $patch)
    $null = & $talosctl @talosArgs 2>&1
    if ( $LASTEXITCODE -ne 0 ) { throw ( "apply-config failed for {0} exit {1}" -f $n.Current, $LASTEXITCODE ) }
  }
}


$cp = Read-NodeIPs -VMs $SelCpVMs -DefaultPrefix $DefaultPrefix -Gateway $Gateway -DNS $DNS
$wk = Read-NodeIPs -VMs $SelWVMs  -DefaultPrefix $DefaultPrefix -Gateway $Gateway -DNS $DNS

$ENDPOINT = ( "https://{0}:6443" -f $cp[0].IP )
$cpYaml   = $paths.ControlPlane
$wkYaml   = $paths.Worker

$talosctl = Get-BinOrThrow -Name 'talosctl' -Why ""
if ( $firstRun -or $Force -or -not ( ( Test-Path $cpYaml ) -and ( Test-Path $wkYaml ) -and ( Test-Path $TALOSCONF ) ) ) {
  Write-Host "Generating PKI and tokens..." -ForegroundColor DarkCyan
  & $talosctl gen config $ClusterName $ENDPOINT --output-dir $paths.Dir --install-disk $InstallDisk --force
  if ( $LASTEXITCODE -ne 0 ) { throw ( "talosctl gen config failed exit {0}" -f $LASTEXITCODE ) }
  Write-Host ( "Created cluster config for '{0}'" -f $ClusterName )
} else {
  Write-Host ( "Reusing existing cluster config in {0}" -f $paths.Dir ) -ForegroundColor Yellow
}

if ( -not ( Test-Path $cpYaml ) ) { throw "Missing controlplane.yaml" }
if ( -not ( Test-Path $wkYaml ) ) { throw "Missing worker.yaml" }

Write-Host "Applying control-plane config..." -ForegroundColor Cyan
Invoke-NodeConfig -nodes $cp -YamlPath $cpYaml -TalosConf $TALOSCONF

if ( $SelWVMs.Count -gt 0 ) {
  Write-Host "Applying worker config..." -ForegroundColor Cyan
  Invoke-NodeConfig -nodes $wk -YamlPath $wkYaml -TalosConf $TALOSCONF
}

if ( $firstRun ) {
  Start-Sleep -Seconds 8
  $bootstrapIP = $cp[0].IP
  Write-Host ( "Waiting for Talos API on {0}:50000 ..." -f $bootstrapIP ) -ForegroundColor Cyan
  if ( -not ( Wait-TcpPort -Target $bootstrapIP -Port 50000 -TimeoutSec 600 ) ) {
    throw ( "Talos API not reachable at {0}:50000 after network switch." -f $bootstrapIP )
  }
  if ( $NtpSettleSeconds -gt 0 ) {
    Write-Host ( "Waiting {0}s for time to settle..." -f $NtpSettleSeconds ) -ForegroundColor DarkGray
    Start-Sleep -Seconds $NtpSettleSeconds
  }
  Write-Host ( "Bootstrapping Kubernetes using {0} ..." -f $bootstrapIP ) -ForegroundColor Cyan
  & $talosctl --talosconfig $TALOSCONF config endpoint $bootstrapIP
  & $talosctl --talosconfig $TALOSCONF config node $bootstrapIP
  & $talosctl --talosconfig $TALOSCONF bootstrap
  if ( $LASTEXITCODE -ne 0 ) { throw ( "Bootstrap failed exit {0}" -f $LASTEXITCODE ) }
  Set-TextUtf8 -Path $paths.EndpointFile -Value $bootstrapIP
  & $talosctl --talosconfig $TALOSCONF --nodes $bootstrapIP kubeconfig --force $paths.Dir
  if ( $LASTEXITCODE -ne 0 ) { throw ( "Failed to fetch kubeconfig exit {0}" -f $LASTEXITCODE ) }
  New-Item -ItemType File -Force -Path $bootMark | Out-Null
} else {
  Write-Host "Cluster already bootstrapped. Skipping bootstrap." -ForegroundColor Yellow
}

if ( Test-Path $paths.Kubeconfig ) {
  Use-Kubeconfig -Path $paths.Kubeconfig -ClusterName $ClusterName
}

if ( -not $KeepIso ) {
  foreach ( $vm in @( $CpVMs + $WVMs ) ) {
    try { Set-VMDvdDrive -VMName $vm -Path $null } catch { }
    try { Set-VMFirmware -VMName $vm -FirstBootDevice ( Get-VMHardDiskDrive -VMName $vm ) } catch { }
  }
} else {
  Write-Host "Keeping ISO attached." -ForegroundColor Yellow
}

Write-Host "Done." -ForegroundColor Green
