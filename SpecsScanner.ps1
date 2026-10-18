<#
.SYNOPSIS
    SpecsScanner - scan every PC specification and render a self-contained HTML report.

.DESCRIPTION
    SpecsScanner collects hardware, operating system, storage, network, security
    and software information from a Windows PC using CIM/WMI, the registry and
    native tools, then renders a single self-contained HTML file with a
    Catppuccin Mocha (dark) / Latte (light) theme. Nothing leaves the machine.

.PARAMETER OutputPath
    Where to write the report. Extension may be .html or .json; the matching
    companion file is written next to it when -Format Both is used.
    Default: SpecsScanner-<hostname>-<timestamp>.html, saved next to this
    script (the folder that also holds specsscanner.cmd).

.PARAMETER Format
    Html (default), Json, or Both.

.PARAMETER Sections
    Limit the scan to specific sections. Accepts section names and the aliases
    "Hardware" and "All". Example: -Sections System,CPU,Storage

.PARAMETER NoOpen
    Do not open the report in the default browser when finished.

.PARAMETER Theme
    Initial report theme: Mocha (default, dark), Latte (light), or Auto
    (follow the operating system preference).

.PARAMETER Accent
    Brand accent color for the report chrome (logo gradient, focus rings,
    active navigation). Any Catppuccin hue name. Default: Mauve.

.PARAMETER Redact
    Share-safe mode. Replaces hostname, user names, serial numbers, UUIDs,
    MAC addresses, IP addresses and the Wi-Fi SSID with placeholders so the
    report can be shared publicly without leaking machine identifiers.

.EXAMPLE
    .\SpecsScanner.ps1

.EXAMPLE
    .\SpecsScanner.ps1 -Format Both -OutputPath C:\temp\myspecs

.EXAMPLE
    .\SpecsScanner.ps1 -Sections Hardware,Network -NoOpen

.EXAMPLE
    .\SpecsScanner.ps1 -Redact -OutputPath .\share-safe.html

.LINK
    https://github.com/KingStan0/SpecsScanner
#>
#Requires -Version 5.1
[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive CLI tool: colored console progress output is intentional; results are written to files.')]
param(
    [Parameter(Position = 0)]
    [string]$OutputPath,

    [ValidateSet('Html', 'Json', 'Both')]
    [string]$Format = 'Html',

    [string[]]$Sections,

    [switch]$NoOpen,

    [ValidateSet('Mocha', 'Latte', 'Auto')]
    [string]$Theme = 'Mocha',

    [ValidateSet('Mauve', 'Lavender', 'Blue', 'Sapphire', 'Sky', 'Teal', 'Green', 'Yellow', 'Peach', 'Maroon', 'Red', 'Pink', 'Flamingo', 'Rosewater')]
    [string]$Accent = 'Mauve',

    [switch]$Redact
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
$Script:Version   = '2.1.4'
$Script:IsAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:RedactMode = [bool]$Redact
$Script:Warnings  = New-Object System.Collections.ArrayList

$Script:SectionTitles = [ordered]@{
    System      = 'System & BIOS'
    CPU         = 'Processor'
    Memory      = 'Memory'
    Graphics    = 'Graphics'
    Displays    = 'Displays'
    Storage     = 'Storage'
    Network     = 'Network'
    Audio       = 'Audio'
    Battery     = 'Battery'
    Security    = 'Security'
    Windows     = 'Windows'
    Peripherals = 'Peripherals'
    Software    = 'Installed Software'
    Services    = 'Services'
}

$Script:SectionAliases = @{
    Hardware = @('System', 'CPU', 'Memory', 'Graphics', 'Displays', 'Storage', 'Audio', 'Battery', 'Peripherals')
    All      = @('System', 'CPU', 'Memory', 'Graphics', 'Displays', 'Storage', 'Network', 'Audio', 'Battery', 'Security', 'Windows', 'Peripherals', 'Software', 'Services')
}

# Per-section presentation: icon key (see Get-SsIcon) and structural accent.
# Structural accents deliberately avoid green/yellow/red, which are reserved
# for status meaning; "green" is only used for the Security section itself.
$Script:SectionMeta = [ordered]@{
    System      = @{ icon = 'board';    accent = 'lavender' }
    CPU         = @{ icon = 'cpu';      accent = 'mauve' }
    Memory      = @{ icon = 'memory';   accent = 'blue' }
    Graphics    = @{ icon = 'gpu';      accent = 'sapphire' }
    Displays    = @{ icon = 'display';  accent = 'sky' }
    Storage     = @{ icon = 'disk';     accent = 'teal' }
    Network     = @{ icon = 'network';  accent = 'pink' }
    Audio       = @{ icon = 'audio';    accent = 'flamingo' }
    Battery     = @{ icon = 'battery';  accent = 'peach' }
    Security    = @{ icon = 'shield';   accent = 'green' }
    Windows     = @{ icon = 'windows';  accent = 'blue' }
    Peripherals = @{ icon = 'usb';      accent = 'rosewater' }
    Software    = @{ icon = 'package';  accent = 'lavender' }
    Services    = @{ icon = 'services'; accent = 'maroon' }
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
function Invoke-Safe {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        $Fallback = $null
    )
    try {
        $result = & $Script
        if ($null -eq $result) { return $Fallback }
        return $result
    } catch {
        return $Fallback
    }
}

function Format-ByteSize {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    try { $b = [double]$Bytes } catch { return $null }
    if ($b -le 0) { return $null }
    if ($b -ge 1TB) { return ('{0:N2} TB' -f ($b / 1TB)) }
    if ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
    if ($b -ge 1KB) { return ('{0:N0} KB' -f ($b / 1KB)) }
    return ('{0:N0} B' -f $b)
}

function Format-CountPhrase {
    # "1 disk" / "3 disks" - avoids "(s)" artifacts in captions.
    param([int]$Count, [string]$Word)
    if ($Count -eq 1) { return ('1 {0}' -f $Word) }
    return ('{0} {1}s' -f $Count, $Word)
}

function ConvertTo-DateTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    # Try the CIM/WMI date format first, then .NET parsing.
    $wmiDate = Invoke-Safe { [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$Value) }
    if ($null -ne $wmiDate) { return $wmiDate }
    try { return [datetime]::Parse([string]$Value) } catch { return $null }
}

function Format-Date {
    param($Value, [string]$Pattern = 'yyyy-MM-dd HH:mm')
    $d = ConvertTo-DateTime $Value
    if ($null -eq $d) { return $null }
    return $d.ToString($Pattern)
}

function Format-GHz {
    param($MHz)
    if ($null -eq $MHz -or [double]$MHz -le 0) { return $null }
    return ('{0:N2} GHz' -f ([double]$MHz / 1000))
}

function Format-NicSpeed {
    param($BitsPerSecond)
    if ($null -eq $BitsPerSecond) { return $null }
    try { $s = [double]$BitsPerSecond } catch { return $null }
    if ($s -le 0) { return $null }
    if ($s -ge 1e9) { return ('{0:N0} Gbps' -f ($s / 1e9)) }
    if ($s -ge 1e6) { return ('{0:N0} Mbps' -f ($s / 1e6)) }
    if ($s -ge 1e3) { return ('{0:N0} Kbps' -f ($s / 1e3)) }
    return ('{0:N0} bps' -f $s)
}

function ConvertFrom-WmiString {
    # Decodes the uint16 arrays used by root\wmi monitor classes (EDID strings).
    param($Arr)
    if ($null -eq $Arr) { return $null }
    $chars = foreach ($c in @($Arr)) {
        if ($c -gt 32 -and $c -lt 65535) { [char]$c }
    }
    $s = (-join $chars).Trim()
    if ($s -eq '') { return $null }
    return $s
}

function ConvertTo-U16Value {
    # root\wmi often returns single uint16 values wrapped in an array.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [array]) {
        if ($Value.Count -eq 0) { return $null }
        return [int]$Value[0]
    }
    return [int]$Value
}

function Convert-RegValueToUInt64 {
    # Registry values may come back as Int64, UInt32 or a REG_BINARY byte array.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]] -or $Value -is [System.Array]) {
        try {
            $bytes = [byte[]]$Value
            if ($bytes.Length -ge 8) { return [System.BitConverter]::ToUInt64($bytes, 0) }
            if ($bytes.Length -ge 4) { return [uint64][System.BitConverter]::ToUInt32($bytes, 0) }
            return $null
        } catch { return $null }
    }
    try { return [uint64]$Value } catch { return $null }
}

function ConvertTo-InstallDateText {
    # Normalises the many junk date formats found in uninstall registry keys.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::None
    if ($v -match '^\d{8}$') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($v, 'yyyyMMdd', $inv, $styles, [ref]$d)) { return $d.ToString('yyyy-MM-dd') }
        if ([datetime]::TryParseExact($v, 'ddMMyyyy', $inv, $styles, [ref]$d)) { return $d.ToString('yyyy-MM-dd') }
        return $null
    }
    if ($v -match '^\d{9,10}$') {
        $unix = Invoke-Safe { [System.DateTimeOffset]::FromUnixTimeSeconds([int64]$v).LocalDateTime }
        if ($null -ne $unix -and $unix.Year -ge 2000 -and $unix.Year -le 2100) { return $unix.ToString('yyyy-MM-dd') }
        return $null
    }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($v, $inv, $styles, [ref]$d)) { return $d.ToString('yyyy-MM-dd') }
    return $null
}

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-StatusClass {
    # Maps well-known state strings to a status color class (ok / warn / bad).
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().ToLowerInvariant()
    $ok   = @('healthy', 'ok', 'good', 'normal', 'licensed', 'activated', 'enabled', 'on', 'yes', 'running', 'online', 'connected', 'fully charged', 'charging', 'up', 'protected', 'installed', 'present', 'secure boot enabled')
    $warn = @('warning', 'degraded', 'unknown', 'limited', 'fair', 'aging', 'partially charged', 'discharging', 'not available', 'unsupported', 'paused', 'stopped')
    $bad  = @('unhealthy', 'critical', 'error', 'failed', 'fail', 'disabled', 'denied', 'not activated', 'unlicensed', 'offline', 'bad', 'replace', 'not connected', 'off', 'no', 'absent')
    if ($ok -contains $v)   { return 'st-ok' }
    if ($bad -contains $v)  { return 'st-bad' }
    if ($warn -contains $v) { return 'st-warn' }
    return $null
}

function ConvertTo-HtmlCell {
    param($Value)
    if ($null -eq $Value) { return '<span class="dim">&mdash;</span>' }
    if ($Value -is [bool]) { $Value = if ($Value) { 'Yes' } else { 'No' } }
    if ($Value -is [array]) {
        $parts = @($Value | Where-Object { $null -ne $_ -and "$_" -ne '' })
        $Value = ($parts -join ', ')
    }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return '<span class="dim">&mdash;</span>' }
    $esc = ConvertTo-HtmlText $s
    $cls = Get-StatusClass $s
    if ($cls) { return ('<span class="{0}">{1}</span>' -f $cls, $esc) }
    return $esc
}

function Write-TextFile {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Resolve-OutputPath {
    param([string]$Path, [string]$Stamp)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $hostPart = $env:COMPUTERNAME
        if ($Script:RedactMode) { $hostPart = 'DESKTOP-EXAMPLE' }
        $root = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($root)) { $root = (Get-Location).Path }
        $base = Join-Path -Path $root -ChildPath ('SpecsScanner-{0}-{1}' -f $hostPart, $Stamp)
    } else {
        $ext = [System.IO.Path]::GetExtension($Path)
        if ($ext -ieq '.html' -or $ext -ieq '.json') {
            $base = $Path.Substring(0, $Path.Length - $ext.Length)
        } else {
            $base = $Path
        }
        $base = [System.IO.Path]::GetFullPath($base)
    }
    $dir = [System.IO.Path]::GetDirectoryName($base)
    if ($dir -and -not [System.IO.Directory]::Exists($dir)) {
        [void][System.IO.Directory]::CreateDirectory($dir)
    }
    return [ordered]@{ html = ($base + '.html'); json = ($base + '.json') }
}

function ConvertTo-Section {
    param([string]$Title)
    return @{
        title    = $Title
        pairs    = [ordered]@{}
        tables   = New-Object System.Collections.ArrayList
        notes    = New-Object System.Collections.ArrayList
        summary  = [ordered]@{}
        subtitle = $null
        widgets  = [ordered]@{}
        skip     = $false
    }
}

function Add-SectionTable {
    param($Section, [string]$Title, $Columns, $Rows)
    $rowsArr = @($Rows | Where-Object { $null -ne $_ })
    if ($rowsArr.Count -eq 0) { return }
    [void]$Section.tables.Add(@{ title = $Title; columns = @($Columns); rows = $rowsArr })
}

# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
function Read-System {
    $sec = ConvertTo-Section 'System & BIOS'
    $cs   = Invoke-Safe { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    $csp  = Invoke-Safe { Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop }
    $bios = Invoke-Safe { Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop }
    $bb   = Invoke-Safe { Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop }
    $enc  = Invoke-Safe { Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop }

    function Get-CleanId {
        param($Value)
        if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
        $v = ([string]$Value).Trim()
        if ($v -match '(?i)to be filled|default string|^none$|^o\.e\.m|^0+$') { return "$v (OEM placeholder)" }
        return $v
    }

    $chassisMap = @{
        1 = 'Other'; 2 = 'Unknown'; 3 = 'Desktop'; 4 = 'Low Profile Desktop'; 5 = 'Pizza Box'
        6 = 'Mini Tower'; 7 = 'Tower'; 8 = 'Portable'; 9 = 'Laptop'; 10 = 'Notebook'
        11 = 'Hand Held'; 12 = 'Docking Station'; 13 = 'All-in-One'; 14 = 'Sub Notebook'
        15 = 'Space-Saving'; 16 = 'Lunch Box'; 17 = 'Main System Chassis'; 18 = 'Expansion Chassis'
        19 = 'Sub Chassis'; 20 = 'Bus Expansion Chassis'; 21 = 'Peripheral Chassis'
        22 = 'Storage Chassis'; 23 = 'Rack Mount Chassis'; 24 = 'Sealed-Case PC'
        30 = 'Tablet'; 31 = 'Convertible'; 32 = 'Detachable'; 35 = 'Mini PC'
    }
    $chassis = $null
    if ($enc -and $enc.ChassisTypes) {
        $names = foreach ($c in $enc.ChassisTypes) {
            if ($chassisMap.ContainsKey([int]$c)) { $chassisMap[[int]$c] } else { 'Type {0}' -f $c }
        }
        $chassis = ($names -join ', ')
    }

    $serial = $null
    if ($csp -and $csp.IdentifyingNumber) { $serial = $csp.IdentifyingNumber }
    elseif ($bios -and $bios.SerialNumber) { $serial = $bios.SerialNumber }

    $domain = $null
    if ($cs) {
        if ($cs.PartOfDomain) { $domain = 'Domain: {0}' -f $cs.Domain }
        else { $domain = 'Workgroup: {0}' -f $cs.Workgroup }
    }

    $vmHint = 'No (physical hardware)'
    if ($cs) {
        $hay = '{0} {1}' -f $cs.Manufacturer, $cs.Model
        if ($hay -match '(?i)VMware|Virtual|VirtualBox|QEMU|KVM|Xen|Parallels|Hyper-V|Amazon EC2|Google Compute|Droplet') {
            $vmHint = 'Yes ({0})' -f $cs.Model
        }
    }

    $sec.pairs['Hostname']          = $env:COMPUTERNAME
    $sec.pairs['Manufacturer']      = $cs.Manufacturer
    $sec.pairs['Model']             = $cs.Model
    $sec.pairs['System type']       = $cs.SystemType
    $sec.pairs['Chassis']           = $chassis
    $sec.pairs['Serial number']     = Get-CleanId $serial
    $sec.pairs['UUID']              = $csp.UUID
    $sec.pairs['Asset tag']         = Get-CleanId $enc.SMBIOSAssetTag
    $sec.pairs['Domain / workgroup'] = $domain
    $sec.pairs['Virtual machine']   = $vmHint

    $sec.pairs['BIOS vendor']   = $bios.Manufacturer
    $sec.pairs['BIOS version']  = $bios.SMBIOSBIOSVersion
    $sec.pairs['BIOS date']     = Format-Date $bios.ReleaseDate 'yyyy-MM-dd'
    $sec.pairs['Board vendor']  = $bb.Manufacturer
    $sec.pairs['Board model']   = $bb.Product
    $sec.pairs['Board version'] = $bb.Version
    $sec.pairs['Board serial']  = Get-CleanId $bb.SerialNumber

    $board = "$($bb.Manufacturer) $($bb.Product)".Trim()
    if ($board -eq '') { $board = $null }
    $sec.summary['Hostname']      = $env:COMPUTERNAME
    $sec.summary['Motherboard']   = $board
    $sec.widgets['chassis']      = $chassis
    $sec.widgets['vm']           = $vmHint
    $sec.widgets['board']        = $board
    $sec.widgets['bios']         = ("$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)").Trim()
    $sec.widgets['manufacturer'] = $cs.Manufacturer
    $sec.widgets['model']        = $cs.Model
    $sec.widgets['domain']       = $domain
    $sec.subtitle = [string]$cs.Model
    return $sec
}

function Read-CPU {
    $sec = ConvertTo-Section 'Processor'
    $cpus = @(Invoke-Safe { Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop } @())
    $cs   = Invoke-Safe { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    if ($cpus.Count -eq 0) {
        [void]$sec.notes.Add('No processor information could be read from WMI.')
        return $sec
    }

    $archMap = @{ 0 = 'x86'; 1 = 'MIPS'; 2 = 'Alpha'; 3 = 'PowerPC'; 5 = 'ARM'; 6 = 'Itanium'; 9 = 'x64'; 12 = 'ARM64' }

    $sec.pairs['Name']        = $cpus[0].Name
    $sec.pairs['Manufacturer'] = $cpus[0].Manufacturer
    $arch = 'Unknown'
    if ($archMap.ContainsKey([int]$cpus[0].Architecture)) { $arch = $archMap[[int]$cpus[0].Architecture] }
    $sec.pairs['Architecture'] = $arch
    $sec.pairs['Cores']        = $cpus[0].NumberOfCores
    $sec.pairs['Threads']      = $cpus[0].NumberOfLogicalProcessors
    $sec.pairs['Max clock (reported)'] = Format-GHz $cpus[0].MaxClockSpeed
    $sec.pairs['Socket']       = $cpus[0].SocketDesignation
    if ($cpus[0].L2CacheSize) { $sec.pairs['L2 cache'] = Format-ByteSize ([double]$cpus[0].L2CacheSize * 1KB) }
    if ($cpus[0].L3CacheSize) { $sec.pairs['L3 cache'] = Format-ByteSize ([double]$cpus[0].L3CacheSize * 1KB) }
    $vt = 'Disabled'; if ($cpus[0].VirtualizationFirmwareEnabled) { $vt = 'Enabled' }
    $sec.pairs['Virtualization (firmware)'] = $vt
    $slat = 'Disabled'; if ($cpus[0].SecondLevelAddressTranslationExtensions) { $slat = 'Enabled' }
    $sec.pairs['SLAT (EPT/NPT)'] = $slat
    if ($cs) {
        $hyp = 'No'; if ($cs.HypervisorPresent) { $hyp = 'Yes' }
        $sec.pairs['Hypervisor present'] = $hyp
    }

    if ($cpus.Count -gt 1) {
        $rows = @()
        foreach ($c in $cpus) {
            $a = 'Unknown'
            if ($archMap.ContainsKey([int]$c.Architecture)) { $a = $archMap[[int]$c.Architecture] }
            $rows += [ordered]@{
                'Processor' = $c.Name; 'Architecture' = $a; 'Cores' = $c.NumberOfCores
                'Threads' = $c.NumberOfLogicalProcessors; 'Max clock' = Format-GHz $c.MaxClockSpeed
                'Socket' = $c.SocketDesignation
            }
        }
        $cols = @(
            [ordered]@{ key = 'Processor'; label = 'Processor' }
            [ordered]@{ key = 'Architecture'; label = 'Architecture' }
            [ordered]@{ key = 'Cores'; label = 'Cores' }
            [ordered]@{ key = 'Threads'; label = 'Threads' }
            [ordered]@{ key = 'Max clock'; label = 'Max clock' }
            [ordered]@{ key = 'Socket'; label = 'Socket' }
        )
        Add-SectionTable -Section $sec -Title 'All physical processors' -Columns $cols -Rows $rows
    }

    $sec.summary['CPU'] = $cpus[0].Name
    $sec.widgets['name']    = $cpus[0].Name
    $sec.widgets['cores']   = [int]$cpus[0].NumberOfCores
    $sec.widgets['threads'] = [int]$cpus[0].NumberOfLogicalProcessors
    $sec.widgets['clock']   = Format-GHz $cpus[0].MaxClockSpeed
    $sec.widgets['l2']      = $null
    $sec.widgets['l3']      = $null
    if ($cpus[0].L2CacheSize) { $sec.widgets['l2'] = Format-ByteSize ([double]$cpus[0].L2CacheSize * 1KB) }
    if ($cpus[0].L3CacheSize) { $sec.widgets['l3'] = Format-ByteSize ([double]$cpus[0].L3CacheSize * 1KB) }
    $subParts = @()
    if ($cpus[0].NumberOfCores -and $cpus[0].NumberOfLogicalProcessors) {
        $subParts += ('{0} cores / {1} threads' -f $cpus[0].NumberOfCores, $cpus[0].NumberOfLogicalProcessors)
    }
    if ($sec.widgets['clock']) { $subParts += ('{0} max' -f $sec.widgets['clock']) }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }
    return $sec
}

function Read-Memory {
    $sec = ConvertTo-Section 'Memory'
    $os    = Invoke-Safe { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    $sticks = @(Invoke-Safe { Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop } @())
    $arr   = Invoke-Safe { Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction Stop }

    if ($os) {
        $totalB = [double]$os.TotalVisibleMemorySize * 1KB
        $freeB  = [double]$os.FreePhysicalMemory * 1KB
        $usedB  = $totalB - $freeB
        $pct = 0.0
        if ($totalB -gt 0) { $pct = ($usedB / $totalB) * 100 }
        $sec.pairs['Total (visible to Windows)'] = Format-ByteSize $totalB
        $sec.pairs['In use']  = ('{0} ({1:N1}%)' -f (Format-ByteSize $usedB), $pct)
        $sec.pairs['Free']    = Format-ByteSize $freeB
        $commitLimit = [double]$os.TotalVirtualMemorySize * 1KB
        $commitFree  = [double]$os.FreeVirtualMemory * 1KB
        if ($commitLimit -gt 0) {
            $sec.pairs['Commit charge'] = ('{0} / {1}' -f (Format-ByteSize ($commitLimit - $commitFree)), (Format-ByteSize $commitLimit))
        }
        $sec.summary['Memory'] = '{0} ({1:N1}% in use)' -f (Format-ByteSize $totalB), $pct
        $sec.widgets['totalBytes'] = $totalB
        $sec.widgets['usedBytes']  = $usedB
        $sec.widgets['freeBytes']  = $freeB
        $sec.widgets['usedPct']    = [Math]::Round($pct, 1)
    }

    $pf = @(Invoke-Safe { Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop } @())
    if ($pf.Count -gt 0) {
        $pfRows = @()
        foreach ($p in $pf) {
            $pfRows += [ordered]@{
                'Page file'   = $p.Name
                'Allocated'   = ('{0:N0} MB' -f [double]$p.AllocatedBaseSize)
                'In use'      = ('{0:N0} MB' -f [double]$p.CurrentUsage)
                'Peak usage'  = ('{0:N0} MB' -f [double]$p.PeakUsage)
            }
        }
        $cols = @(
            [ordered]@{ key = 'Page file'; label = 'Page file' }
            [ordered]@{ key = 'Allocated'; label = 'Allocated' }
            [ordered]@{ key = 'In use'; label = 'In use' }
            [ordered]@{ key = 'Peak usage'; label = 'Peak usage' }
        )
        Add-SectionTable -Section $sec -Title 'Page file' -Columns $cols -Rows $pfRows
    }

    if ($arr) {
        $slots = $arr.MemoryDevices
        $usedSlots = $sticks.Count
        if ($slots) { $sec.pairs['Memory slots'] = '{0} used of {1}' -f $usedSlots, $slots }
        if ($slots) { $sec.widgets['slots'] = $slots }
        if ($arr.MaxCapacityEx) {
            $maxB = [double]$arr.MaxCapacityEx * 1KB
            if ($maxB -gt 0) { $sec.pairs['Max supported memory'] = Format-ByteSize $maxB }
        }
    }

    $memTypeMap = @{
        0 = 'Unknown'; 20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4'
        27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5'
    }
    $ffMap = @{
        1 = 'Other'; 2 = 'Unknown'; 7 = 'SIMM'; 8 = 'DIMM'; 9 = 'TSOP'; 10 = 'PGA'; 11 = 'RIMM'
        12 = 'SODIMM'; 13 = 'SRIMM'; 14 = 'SMD'; 23 = 'LGA'; 24 = 'FB-DIMM'
    }

    if ($sticks.Count -gt 0) {
        $rows = @()
        $stickWidgets = @()
        $installedBytes = 0.0
        foreach ($m in $sticks) {
            $typeVal = $null
            if ($m.SMBIOSMemoryType) { $typeVal = [int]$m.SMBIOSMemoryType }
            elseif ($m.MemoryType)  { $typeVal = [int]$m.MemoryType }
            $type = $null
            if ($null -ne $typeVal -and $memTypeMap.ContainsKey($typeVal)) { $type = $memTypeMap[$typeVal] }
            elseif ($null -ne $typeVal) { $type = 'Code {0}' -f $typeVal }
            $ff = $null
            if ($m.FormFactor -and $ffMap.ContainsKey([int]$m.FormFactor)) { $ff = $ffMap[[int]$m.FormFactor] }
            $speed = $m.ConfiguredClockSpeed
            if (-not $speed -or [int]$speed -le 0) { $speed = $m.Speed }
            $speedStr = $null
            if ($speed -and [int]$speed -gt 0) { $speedStr = '{0} MT/s' -f $speed }
            $slot = "$($m.BankLabel) $($m.DeviceLocator)".Trim()
            $rows += [ordered]@{
                'Slot'        = $slot
                'Size'        = Format-ByteSize $m.Capacity
                'Speed'       = $speedStr
                'Type'        = $type
                'Form factor' = $ff
                'Manufacturer' = $m.Manufacturer
                'Part number' = ([string]$m.PartNumber).Trim()
                'Serial'      = ([string]$m.SerialNumber).Trim()
                'Voltage'     = if ([double]$m.ConfiguredVoltage -gt 0) { '{0:N2} V' -f ([double]$m.ConfiguredVoltage / 1000) } else { $null }
            }
            $stickWidgets += [ordered]@{
                slot  = $slot
                size  = Format-ByteSize $m.Capacity
                speed = $speedStr
                type  = $type
                mfr   = ([string]$m.Manufacturer).Trim()
                part  = ([string]$m.PartNumber).Trim()
            }
            if ($m.Capacity) { $installedBytes += [double]$m.Capacity }
        }
        $sec.widgets['sticks'] = $stickWidgets
        if ($installedBytes -gt 0) { $sec.widgets['installedBytes'] = $installedBytes }
        $cols = @(
            [ordered]@{ key = 'Slot'; label = 'Slot' }
            [ordered]@{ key = 'Size'; label = 'Size' }
            [ordered]@{ key = 'Speed'; label = 'Speed' }
            [ordered]@{ key = 'Type'; label = 'Type' }
            [ordered]@{ key = 'Form factor'; label = 'Form factor' }
            [ordered]@{ key = 'Manufacturer'; label = 'Manufacturer' }
            [ordered]@{ key = 'Part number'; label = 'Part number' }
            [ordered]@{ key = 'Serial'; label = 'Serial' }
            [ordered]@{ key = 'Voltage'; label = 'Voltage' }
        )
        Add-SectionTable -Section $sec -Title ('Memory modules ({0})' -f $sticks.Count) -Columns $cols -Rows $rows
    } else {
        [void]$sec.notes.Add('No memory module details available (SMBIOS data missing).')
    }

    $subParts = @()
    if ($sec.widgets['totalBytes']) { $subParts += Format-ByteSize $sec.widgets['totalBytes'] }
    if ($sec.widgets['usedPct']) { $subParts += ('{0:N1}% in use' -f $sec.widgets['usedPct']) }
    if ($sticks.Count -gt 0) { $subParts += (Format-CountPhrase $sticks.Count 'module') }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }
    return $sec
}

function Get-VramMap {
    # Reads true VRAM sizes from the display class registry key; WMI's AdapterRAM
    # is a 32-bit value capped at ~4 GB.
    $map = @{}
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    # Only numeric adapter subkeys (0000, 0001, ...) - the class key also contains
    # a protected 'Properties' subkey that would otherwise abort enumeration.
    $keys = @(Get-ChildItem -Path $base -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })
    foreach ($k in $keys) {
        $props = Invoke-Safe { Get-ItemProperty -Path $k.PSPath -ErrorAction Stop }
        if ($null -eq $props) { continue }
        $desc = [string]$props.DriverDesc
        if (-not $desc) { continue }
        $size = $null
        if ($props.PSObject.Properties['HardwareInformation.qwMemorySize']) {
            $size = Convert-RegValueToUInt64 $props.'HardwareInformation.qwMemorySize'
        }
        if (-not $size -and $props.PSObject.Properties['HardwareInformation.MemorySize']) {
            $size = Convert-RegValueToUInt64 $props.'HardwareInformation.MemorySize'
        }
        if ($size -and $size -gt 0) { $map[$desc] = $size }
    }
    return $map
}

function Read-GPU {
    $sec = ConvertTo-Section 'Graphics'
    $vcs = @(Invoke-Safe { Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop } @())
    if ($vcs.Count -eq 0) {
        [void]$sec.notes.Add('No video controller information could be read from WMI.')
        return $sec
    }

    $vramMap = Invoke-Safe { Get-VramMap } @{}
    $usedCapped = $false

    # Rank adapters so the report leads with the real GPU: physical adapters
    # with readable VRAM first (largest first), then other physical adapters,
    # then virtual/basic/remote display adapters (Parsec, Basic Display, ...).
    $ranked = @()
    foreach ($vc in $vcs) {
        $vram = $null
        foreach ($key in $vramMap.Keys) {
            if ($key -and ($vc.Name -like "*$key*" -or $key -like "*$($vc.Name)*")) {
                $vram = $vramMap[$key]
                break
            }
        }
        $rank = 0
        if ($vc.Name -match '(?i)virtual|basic display|basic render|remote display|indirect display|parsec|splashtop|mirror driver') { $rank = 2 }
        elseif (-not $vram -and -not ($vc.AdapterRAM -and [double]$vc.AdapterRAM -gt 0)) { $rank = 1 }
        $ranked += [pscustomobject]@{ vc = $vc; vram = $vram; rank = $rank }
    }
    $ranked = @($ranked | Sort-Object -Property @{ Expression = { $_.rank } },
        @{ Expression = { if ($_.vram) { 0 - [double]$_.vram } else { 0 } } },
        @{ Expression = { [string]$_.vc.Name } })

    $rows = @()
    $adapterWidgets = @()

    foreach ($item in $ranked) {
        $vc = $item.vc
        $vram = $item.vram
        $vramText = $null
        if ($vram) {
            $vramText = Format-ByteSize $vram
        } elseif ($vc.AdapterRAM -and [double]$vc.AdapterRAM -gt 0) {
            $vramText = (Format-ByteSize ([double]$vc.AdapterRAM)) + ' (WMI value, capped at 4 GB)'
            $usedCapped = $true
        }

        $mode = $null
        if ($vc.CurrentHorizontalResolution -and $vc.CurrentVerticalResolution) {
            $mode = '{0} x {1}' -f $vc.CurrentHorizontalResolution, $vc.CurrentVerticalResolution
            if ($vc.CurrentRefreshRate) { $mode += ' @ {0} Hz' -f $vc.CurrentRefreshRate }
        } elseif ($vc.VideoModeDescription) {
            $mode = $vc.VideoModeDescription
        }

        $rows += [ordered]@{
            'Adapter'        = $vc.Name
            'VRAM'           = $vramText
            'Driver version' = $vc.DriverVersion
            'Driver date'    = Format-Date $vc.DriverDate 'yyyy-MM-dd'
            'Current mode'   = $mode
            'Status'         = $vc.Status
        }
        $adapterWidgets += [ordered]@{
            name   = $vc.Name
            vram   = $vramText
            driver = $vc.DriverVersion
            mode   = $mode
            status = $vc.Status
        }
    }
    $sec.widgets['adapters'] = $adapterWidgets

    $cols = @(
        [ordered]@{ key = 'Adapter'; label = 'Adapter' }
        [ordered]@{ key = 'VRAM'; label = 'VRAM' }
        [ordered]@{ key = 'Driver version'; label = 'Driver version' }
        [ordered]@{ key = 'Driver date'; label = 'Driver date' }
        [ordered]@{ key = 'Current mode'; label = 'Current mode' }
        [ordered]@{ key = 'Status'; label = 'Status' }
    )
    Add-SectionTable -Section $sec -Title ('Adapters ({0})' -f $vcs.Count) -Columns $cols -Rows $rows

    if ($usedCapped) {
        [void]$sec.notes.Add('At least one adapter reports its VRAM through the WMI 32-bit field, which is capped at 4 GB. The true size could not be read from the registry for that adapter.')
    }

    $names = @($vcs | ForEach-Object { $_.Name } | Where-Object { $_ })
    $sec.summary['GPU'] = ($names | Select-Object -First 2) -join ' + '
    $subParts = @()
    if ($adapterWidgets.Count -gt 0) { $subParts += $adapterWidgets[0].name }
    if ($adapterWidgets.Count -gt 0 -and $adapterWidgets[0].vram) { $subParts += $adapterWidgets[0].vram }
    if ($vcs.Count -gt 1) { $subParts += ('{0} adapters' -f $vcs.Count) }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }
    return $sec
}

function Read-Display {
    $sec = ConvertTo-Section 'Displays'
    $mons  = @(Invoke-Safe { Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction Stop } @())
    $basic = @(Invoke-Safe { Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorBasicDisplayParams -ErrorAction Stop } @())
    $bright = @(Invoke-Safe { Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorBrightness -ErrorAction Stop } @())

    if ($mons.Count -eq 0) {
        [void]$sec.notes.Add('No EDID monitor data was returned by WMI. This is normal on some desktops, virtual machines, or when a monitor is routed through a KVM/hub.')
        return $sec
    }

    $rows = @()
    $monWidgets = @()
    foreach ($m in $mons) {
        $friendly = ConvertFrom-WmiString $m.UserFriendlyName
        $mfr = ConvertFrom-WmiString $m.ManufacturerName
        $sn = ConvertFrom-WmiString $m.SerialNumberID
        $code = $null
        $pcVal = ConvertTo-U16Value $m.ProductCodeID
        if ($null -ne $pcVal) { $code = '{0:X4}' -f $pcVal }

        $sizeText = $null
        $b = $basic | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        if ($b) {
            $wcm = ConvertTo-U16Value $b.MaxHorizontalImageSize
            $hcm = ConvertTo-U16Value $b.MaxVerticalImageSize
            if ($wcm -and $hcm -and $wcm -gt 0 -and $hcm -gt 0) {
                $diag = [Math]::Round([Math]::Sqrt(([double]$wcm * $wcm) + ([double]$hcm * $hcm)) / 2.54, 1)
                $sizeText = '{0} in ({1:N0} x {2:N0} cm)' -f $diag, $wcm, $hcm
            }
        }

        $brText = $null
        $br = $bright | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        if ($br) {
            $brightVal = ConvertTo-U16Value $br.CurrentBrightness
            if ($null -ne $brightVal) { $brText = '{0} %' -f $brightVal }
        }

        $year = ConvertTo-U16Value $m.YearOfManufacture
        $week = ConvertTo-U16Value $m.WeekOfManufacture
        $mfg = $null
        if ($year -and $year -gt 0) {
            $mfg = [string]$year
            if ($week -and $week -gt 0) { $mfg += ' (week {0})' -f $week }
        }

        $rows += [ordered]@{
            'Monitor'      = $friendly
            'Manufacturer' = $mfr
            'Product code' = $code
            'Serial'       = $sn
            'Screen size'  = $sizeText
            'Brightness'   = $brText
            'Manufactured' = $mfg
        }
        $monWidgets += [ordered]@{
            name  = $friendly
            mfr   = $mfr
            size  = $sizeText
            code  = $code
            serial = $sn
            bright = $brText
        }
    }
    $sec.widgets['monitors'] = $monWidgets

    $cols = @(
        [ordered]@{ key = 'Monitor'; label = 'Monitor' }
        [ordered]@{ key = 'Manufacturer'; label = 'Manufacturer' }
        [ordered]@{ key = 'Product code'; label = 'Product code' }
        [ordered]@{ key = 'Serial'; label = 'Serial' }
        [ordered]@{ key = 'Screen size'; label = 'Screen size' }
        [ordered]@{ key = 'Brightness'; label = 'Brightness' }
        [ordered]@{ key = 'Manufactured'; label = 'Manufactured' }
    )
    Add-SectionTable -Section $sec -Title ('Detected monitors ({0})' -f $mons.Count) -Columns $cols -Rows $rows
    $sec.summary['Displays'] = [string]$mons.Count
    $subParts = @()
    if ($monWidgets.Count -gt 0) {
        $subParts += (Format-CountPhrase $monWidgets.Count 'monitor')
        if ($monWidgets[0].name) { $subParts += $monWidgets[0].name }
        if ($monWidgets[0].size) { $subParts += $monWidgets[0].size }
    }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }
    return $sec
}

function Read-Storage {
    $sec = ConvertTo-Section 'Storage'
    $disks = @(Invoke-Safe { Get-PhysicalDisk -ErrorAction Stop } @())
    $diskRows = @()
    $diskWidgets = @()
    $relFail = $false
    $usedFallback = $false

    if ($disks.Count -gt 0) {
        foreach ($d in $disks) {
            $rel = Invoke-Safe { Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction Stop }
            if (-not $rel) { $relFail = $true }
            $media = [string]$d.MediaType
            if ($media -eq 'Unspecified' -and [string]$d.BusType -match 'NVMe') { $media = 'SSD (NVMe)' }
            $temp = $null; $wear = $null; $hours = $null
            $tempNum = $null; $wearNum = $null
            if ($rel) {
                if ($rel.Temperature -and [int]$rel.Temperature -gt 0) { $temp = '{0} C' -f $rel.Temperature; $tempNum = [int]$rel.Temperature }
                if ($null -ne $rel.Wear -and [int]$rel.Wear -ge 0) { $wear = '{0} %' -f $rel.Wear; $wearNum = [int]$rel.Wear }
                if ($rel.PowerOnHours -and [int]$rel.PowerOnHours -gt 0) { $hours = [string]$rel.PowerOnHours }
            }
            $diskRows += [ordered]@{
                'Disk'           = $d.FriendlyName
                'Type'           = $media
                'Bus'            = [string]$d.BusType
                'Size'           = Format-ByteSize $d.Size
                'Health'         = [string]$d.HealthStatus
                'Temperature'    = $temp
                'Wear'           = $wear
                'Power-on hours' = $hours
                'Firmware'       = $d.FirmwareVersion
                'Serial'         = ([string]$d.SerialNumber).Trim()
            }
            $diskWidgets += [ordered]@{
                name    = $d.FriendlyName
                type    = $media
                bus     = [string]$d.BusType
                size    = Format-ByteSize $d.Size
                health  = [string]$d.HealthStatus
                temp    = $temp
                tempNum = $tempNum
                wear    = $wear
                wearNum = $wearNum
                hours   = $hours
            }
        }
    } else {
        $usedFallback = $true
        $wd = @(Invoke-Safe { Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop } @())
        foreach ($d in $wd) {
            $diskRows += [ordered]@{
                'Disk'           = $d.Model
                'Type'           = $d.MediaType
                'Bus'            = $d.InterfaceType
                'Size'           = Format-ByteSize $d.Size
                'Health'         = $d.Status
                'Temperature'    = $null
                'Wear'           = $null
                'Power-on hours' = $null
                'Firmware'       = $d.FirmwareRevision
                'Serial'         = ([string]$d.SerialNumber).Trim()
            }
        }
    }

    if ($diskRows.Count -gt 0) {
        $cols = @(
            [ordered]@{ key = 'Disk'; label = 'Disk' }
            [ordered]@{ key = 'Type'; label = 'Type' }
            [ordered]@{ key = 'Bus'; label = 'Bus' }
            [ordered]@{ key = 'Size'; label = 'Size' }
            [ordered]@{ key = 'Health'; label = 'Health' }
            [ordered]@{ key = 'Temperature'; label = 'Temp' }
            [ordered]@{ key = 'Wear'; label = 'Wear' }
            [ordered]@{ key = 'Power-on hours'; label = 'Hours' }
            [ordered]@{ key = 'Firmware'; label = 'Firmware' }
            [ordered]@{ key = 'Serial'; label = 'Serial' }
        )
        Add-SectionTable -Section $sec -Title ('Physical disks ({0})' -f $diskRows.Count) -Columns $cols -Rows $diskRows
    }

    # Disk number -> friendly name (for volume mapping), requires elevation on most systems.
    $diskNameById = @{}
    $gd = @(Invoke-Safe { Get-Disk -ErrorAction Stop } @())
    foreach ($d in $gd) { $diskNameById[[int]$d.Number] = $d.FriendlyName }
    $letterToDisk = @{}
    $gp = @(Invoke-Safe { Get-Partition -ErrorAction Stop } @())
    foreach ($p in $gp) {
        if ($p.DriveLetter) { $letterToDisk[[string]$p.DriveLetter] = [int]$p.DiskNumber }
    }

    # Volumes - unified from Get-Volume or Win32_LogicalDisk.
    $volObjs = @()
    $gv = @(Invoke-Safe { Get-Volume -ErrorAction Stop } @())
    $skippedVols = 0
    if ($gv.Count -gt 0) {
        foreach ($v in $gv) {
            if (-not $v.DriveLetter) { $skippedVols++; continue }
            $volObjs += [ordered]@{
                Letter = [string]$v.DriveLetter; Label = $v.FileSystemLabel; FS = $v.FileSystem
                Type = [string]$v.DriveType; Size = [double]$v.Size; Free = [double]$v.SizeRemaining
                Health = [string]$v.HealthStatus
            }
        }
    } else {
        $ld = @(Invoke-Safe { Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop } @())
        $typeMap = @{ 3 = 'Fixed'; 4 = 'Network'; 5 = 'CD/DVD'; 2 = 'Removable' }
        foreach ($v in $ld) {
            $t = 'Unknown'
            if ($typeMap.ContainsKey([int]$v.DriveType)) { $t = $typeMap[[int]$v.DriveType] }
            $volObjs += [ordered]@{
                Letter = [string]$v.DeviceID.Substring(0, 1); Label = $v.VolumeName; FS = $v.FileSystem
                Type = $t; Size = [double]$v.Size; Free = [double]$v.FreeSpace; Health = $null
            }
        }
    }

    $volRows = @()
    $volWidgets = @()
    $totalFree = 0.0
    $totalSize = 0.0
    foreach ($v in ($volObjs | Sort-Object { $_.Letter })) {
        $freePctText = $null
        $freePctVal = $null
        if ($v.Size -gt 0) {
            $freePctText = '{0:N1} %' -f (($v.Free / $v.Size) * 100)
            $freePctVal = [Math]::Round(($v.Free / $v.Size) * 100, 1)
            $totalFree += $v.Free
            $totalSize += $v.Size
        }
        $diskName = $null
        if ($letterToDisk.ContainsKey($v.Letter)) {
            $dn = $letterToDisk[$v.Letter]
            if ($diskNameById.ContainsKey($dn)) { $diskName = $diskNameById[$dn] }
        }
        $freeText = $null
        if ($v.Size -gt 0) { $freeText = ('{0} ({1})' -f (Format-ByteSize $v.Free), $freePctText) }
        else { $freeText = Format-ByteSize $v.Free }
        $volRows += [ordered]@{
            'Drive'       = ('{0}:' -f $v.Letter)
            'Label'       = $v.Label
            'File system' = $v.FS
            'Type'        = $v.Type
            'Size'        = Format-ByteSize $v.Size
            'Free'        = $freeText
            'Health'      = $v.Health
            'Physical disk' = $diskName
        }
        $volWidgets += [ordered]@{
            letter  = ('{0}:' -f $v.Letter)
            label   = $v.Label
            fs      = $v.FS
            type    = $v.Type
            size    = $v.Size
            free    = $v.Free
            freePct = $freePctVal
            health  = $v.Health
        }
    }

    if ($volRows.Count -gt 0) {
        $cols = @(
            [ordered]@{ key = 'Drive'; label = 'Drive' }
            [ordered]@{ key = 'Label'; label = 'Label' }
            [ordered]@{ key = 'File system'; label = 'File system' }
            [ordered]@{ key = 'Type'; label = 'Type' }
            [ordered]@{ key = 'Size'; label = 'Size' }
            [ordered]@{ key = 'Free'; label = 'Free' }
            [ordered]@{ key = 'Health'; label = 'Health' }
            [ordered]@{ key = 'Physical disk'; label = 'Physical disk' }
        )
        Add-SectionTable -Section $sec -Title ('Volumes ({0})' -f $volRows.Count) -Columns $cols -Rows $volRows
    }

    $partRows = @()
    $wdp = @(Invoke-Safe { Get-CimInstance -ClassName Win32_DiskPartition -ErrorAction Stop } @())
    foreach ($p in $wdp) {
        $flags = New-Object System.Collections.ArrayList
        if ($p.Bootable) { [void]$flags.Add('Boot') }
        if ($p.PrimaryPartition) { [void]$flags.Add('Primary') }
        if ($p.RecognizedPartition) { [void]$flags.Add('Recognized') }
        $partRows += [ordered]@{
            'Disk'      = 'Disk {0}' -f $p.DiskIndex
            'Partition' = $p.Index
            'Type'      = $p.Type
            'Size'      = Format-ByteSize $p.Size
            'Flags'     = ($flags -join ', ')
        }
    }
    if ($partRows.Count -gt 0) {
        $cols = @(
            [ordered]@{ key = 'Disk'; label = 'Disk' }
            [ordered]@{ key = 'Partition'; label = '#' }
            [ordered]@{ key = 'Type'; label = 'Type' }
            [ordered]@{ key = 'Size'; label = 'Size' }
            [ordered]@{ key = 'Flags'; label = 'Flags' }
        )
        Add-SectionTable -Section $sec -Title ('Partitions ({0})' -f $partRows.Count) -Columns $cols -Rows $partRows
    }

    $storageSummary = $null
    if ($totalSize -gt 0) {
        $storageSummary = '{0} total, {1} free' -f (Format-ByteSize $totalSize), (Format-ByteSize $totalFree)
    }
    $sec.summary['Storage'] = $storageSummary
    $sec.widgets['disks'] = $diskWidgets
    $sec.widgets['volumes'] = $volWidgets
    $sec.widgets['totalBytes'] = $totalSize
    $sec.widgets['freeBytes'] = $totalFree
    $subParts = @()
    if ($diskWidgets.Count -gt 0) { $subParts += (Format-CountPhrase $diskWidgets.Count 'disk') }
    if ($storageSummary) { $subParts += $storageSummary }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }

    if ($usedFallback) { [void]$sec.notes.Add('Detailed storage data was unavailable; basic WMI disk information is shown instead.') }
    if ($relFail) {
        if ($Script:IsAdmin) { [void]$sec.notes.Add('This drive does not expose SMART reliability counters.') }
        else { [void]$sec.notes.Add('SMART details (temperature, wear, power-on hours) require running SpecsScanner as Administrator.') }
    }
    if ($skippedVols -gt 0) { [void]$sec.notes.Add(('{0} system or hidden volumes without a drive letter are not listed.' -f $skippedVols)) }
    return $sec
}

function Read-Network {
    $sec = ConvertTo-Section 'Network'
    $cfgs = @(Invoke-Safe { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop } @())
    $cfgByIndex = @{}
    foreach ($c in $cfgs) { $cfgByIndex[[int]$c.Index] = $c }

    $adapters = @(Invoke-Safe { Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' -ErrorAction Stop } @())
    if ($adapters.Count -eq 0) {
        $adapters = @(Invoke-Safe { Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop | Where-Object { $_.NetConnectionID } } @())
    }

    if ($adapters.Count -eq 0) {
        [void]$sec.notes.Add('No physical network adapters were found.')
        return $sec
    }

    $rows = @()
    $connWidgets = @()
    foreach ($a in ($adapters | Sort-Object NetConnectionID, Name)) {
        $cfg = $null
        if ($cfgByIndex.ContainsKey([int]$a.Index)) { $cfg = $cfgByIndex[[int]$a.Index] }

        $ipv4 = $null; $subnet = $null; $gw = $null; $dns = $null; $dhcp = $null
        if ($cfg) {
            if ($cfg.IPAddress) {
                $ipv4 = @($cfg.IPAddress) | Where-Object { $_ -match '^\d{1,3}\.' -and $_ -notmatch '^169\.254\.' } | Select-Object -First 1
            }
            if ($cfg.IPSubnet) {
                $subnet = @($cfg.IPSubnet) | Where-Object { $_ -match '^\d{1,3}\.' } | Select-Object -First 1
            }
            if ($cfg.DefaultIPGateway) { $gw = @($cfg.DefaultIPGateway)[0] }
            if ($cfg.DNSServerSearchOrder) { $dns = (@($cfg.DNSServerSearchOrder) -join ', ') }
            if ($null -ne $cfg.DHCPEnabled) {
                $dhcp = 'Disabled'
                if ($cfg.DHCPEnabled) {
                    $dhcp = 'Enabled'
                    if ($cfg.DHCPServer) { $dhcp += ' ({0})' -f $cfg.DHCPServer }
                }
            }
        }

        $conn = [string]$a.NetConnectionID
        if (-not $conn) { $conn = [string]$a.Name }
        $type = 'Ethernet'
        $nameProbe = "$conn $($a.Name)"
        if ($nameProbe -match '(?i)wi-?fi|wireless|wlan') { $type = 'Wi-Fi' }
        elseif ($nameProbe -match '(?i)bluetooth') { $type = 'Bluetooth' }
        elseif ($nameProbe -match '(?i)vpn|tap|tun') { $type = 'VPN' }

        $status = 'Unknown'
        if ($null -ne $a.NetConnectionStatus) {
            $stMap = @{ 0 = 'Disconnected'; 1 = 'Connecting'; 2 = 'Connected'; 3 = 'Disconnecting'; 4 = 'Hardware not present'; 5 = 'Hardware disabled'; 6 = 'Hardware malfunction'; 7 = 'Media disconnected'; 8 = 'Authenticating'; 9 = 'Authentication succeeded'; 10 = 'Authentication failed'; 11 = 'Invalid address'; 12 = 'Credentials required' }
            $st = [int]$a.NetConnectionStatus
            if ($stMap.ContainsKey($st)) { $status = $stMap[$st] } else { $status = 'Code {0}' -f $st }
        }
        if ($null -ne $a.NetEnabled -and -not $a.NetEnabled) { $status = 'Disabled' }

        $speed = $null
        if ($a.Speed -and [double]$a.Speed -gt 0 -and $status -eq 'Connected') { $speed = Format-NicSpeed $a.Speed }

        $rows += [ordered]@{
            'Connection' = $conn
            'Type'       = $type
            'Status'     = $status
            'Speed'      = $speed
            'MAC'        = $a.MACAddress
            'IPv4'       = $ipv4
            'Subnet'     = $subnet
            'Gateway'    = $gw
            'DNS'        = $dns
            'DHCP'       = $dhcp
            'Adapter'    = $a.Name
        }
        $connWidgets += [ordered]@{
            conn      = $conn
            type      = $type
            status    = $status
            connected = ($status -eq 'Connected')
            speed     = $speed
            mac       = $a.MACAddress
            ipv4      = $ipv4
            subnet    = $subnet
            gateway   = $gw
            dns       = $dns
            dhcp      = $dhcp
            adapter   = $a.Name
        }
    }

    $cols = @(
        [ordered]@{ key = 'Connection'; label = 'Connection' }
        [ordered]@{ key = 'Type'; label = 'Type' }
        [ordered]@{ key = 'Status'; label = 'Status' }
        [ordered]@{ key = 'Speed'; label = 'Speed' }
        [ordered]@{ key = 'MAC'; label = 'MAC address' }
        [ordered]@{ key = 'IPv4'; label = 'IPv4' }
        [ordered]@{ key = 'Subnet'; label = 'Subnet' }
        [ordered]@{ key = 'Gateway'; label = 'Gateway' }
        [ordered]@{ key = 'DNS'; label = 'DNS' }
        [ordered]@{ key = 'DHCP'; label = 'DHCP' }
        [ordered]@{ key = 'Adapter'; label = 'Adapter' }
    )
    Add-SectionTable -Section $sec -Title ('Adapters ({0})' -f $rows.Count) -Columns $cols -Rows $rows

    # Wi-Fi details via netsh (works without elevation in most cases).
    $wl = Invoke-Safe { netsh wlan show interfaces }
    if ($wl) {
        $text = $wl -join "`n"
        if ($text -match '(?im)^\s*SSID\s*:\s*(.+)$') { $sec.pairs['Wi-Fi network (SSID)'] = $Matches[1].Trim() }
        if ($text -match '(?im)^\s*Signal\s*:\s*(.+)$') { $sec.pairs['Wi-Fi signal'] = $Matches[1].Trim() }
        if ($text -match '(?im)^\s*Radio type\s*:\s*(.+)$') { $sec.pairs['Wi-Fi radio type'] = $Matches[1].Trim() }
        if ($text -match '(?im)^\s*Channel\s*:\s*(.+)$') { $sec.pairs['Wi-Fi channel'] = $Matches[1].Trim() }
        if ($text -match '(?im)^\s*Receive rate.*:\s*(.+)$') { $sec.pairs['Wi-Fi receive rate'] = $Matches[1].Trim() }
        if ($text -match '(?im)^\s*Transmit rate.*:\s*(.+)$') { $sec.pairs['Wi-Fi transmit rate'] = $Matches[1].Trim() }
        if ($text -match '(?im)^\s*Authentication\s*:\s*(.+)$') { $sec.pairs['Wi-Fi authentication'] = $Matches[1].Trim() }
    }

    $connAdapters = @($rows | Where-Object { $_.Status -eq 'Connected' })
    if ($connAdapters.Count -gt 0) {
        $sec.summary['Network'] = '{0} connected ({1})' -f $connAdapters.Count, $connAdapters[0].Type
    }
    $sec.widgets['connections'] = $connWidgets
    $subParts = @()
    $firstConn = $connWidgets | Where-Object { $_.connected } | Select-Object -First 1
    if ($firstConn) {
        $subParts += $firstConn.type
        if ($firstConn.speed) { $subParts += $firstConn.speed }
        if ($firstConn.ipv4) { $subParts += $firstConn.ipv4 }
    } else {
        $subParts += (Format-CountPhrase $connWidgets.Count 'adapter') + ' / none connected'
    }
    $sec.subtitle = ($subParts -join ' / ')
    return $sec
}

function Read-Audio {
    $sec = ConvertTo-Section 'Audio'
    $devs = @(Invoke-Safe { Get-CimInstance -ClassName Win32_SoundDevice -ErrorAction Stop } @())
    $rows = @()
    foreach ($d in $devs) {
        $rows += [ordered]@{
            'Device'       = $d.Name
            'Manufacturer' = $d.Manufacturer
            'Status'       = $d.Status
        }
    }
    if ($rows.Count -gt 0) {
        $cols = @(
            [ordered]@{ key = 'Device'; label = 'Device' }
            [ordered]@{ key = 'Manufacturer'; label = 'Manufacturer' }
            [ordered]@{ key = 'Status'; label = 'Status' }
        )
        Add-SectionTable -Section $sec -Title ('Sound devices ({0})' -f $rows.Count) -Columns $cols -Rows $rows
    }

    $endpoints = @(Invoke-Safe { Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='AudioEndpoint'" -ErrorAction Stop } @())
    $epRows = @()
    foreach ($e in $endpoints) {
        $epRows += [ordered]@{
            'Endpoint'     = $e.Name
            'Manufacturer' = $e.Manufacturer
            'Status'       = $e.Status
        }
    }
    if ($epRows.Count -gt 0) {
        $cols = @(
            [ordered]@{ key = 'Endpoint'; label = 'Endpoint' }
            [ordered]@{ key = 'Manufacturer'; label = 'Manufacturer' }
            [ordered]@{ key = 'Status'; label = 'Status' }
        )
        Add-SectionTable -Section $sec -Title ('Audio endpoints ({0})' -f $epRows.Count) -Columns $cols -Rows $epRows
    }

    if ($rows.Count -eq 0 -and $epRows.Count -eq 0) {
        [void]$sec.notes.Add('No audio devices were reported by WMI.')
    }
    $subParts = @()
    if ($rows.Count -gt 0) { $subParts += (Format-CountPhrase $rows.Count 'device') }
    if ($epRows.Count -gt 0) { $subParts += (Format-CountPhrase $epRows.Count 'endpoint') }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }
    return $sec
}

function Read-Battery {
    $sec = ConvertTo-Section 'Battery'
    $bats = @(Invoke-Safe { Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop } @())
    $designed = Invoke-Safe { Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction Stop }
    $fullCap  = Invoke-Safe { Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop }
    $cycles   = Invoke-Safe { Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryCycleCount -ErrorAction Stop }

    if ($bats.Count -eq 0 -and -not $designed) {
        $sec.skip = $true
        return $sec
    }

    $statusMap = @{
        1 = 'Other'; 2 = 'Unknown'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'; 6 = 'Charging'
        7 = 'Charging (high)'; 8 = 'Charging (low)'; 9 = 'Charging (critical)'; 10 = 'Undefined'; 11 = 'Partially charged'
    }
    $chemMap = @{ 1 = 'Other'; 2 = 'Unknown'; 3 = 'Lead acid'; 4 = 'Nickel cadmium'; 5 = 'Nickel metal hydride'; 6 = 'Lithium-ion'; 7 = 'Zinc air'; 8 = 'Lithium polymer' }

    if ($bats.Count -gt 0) {
        $b = $bats[0]
        $sec.pairs['Battery'] = $b.Name
        $sec.pairs['Charge remaining'] = '{0} %' -f $b.EstimatedChargeRemaining
        if ($null -ne $b.BatteryStatus -and $statusMap.ContainsKey([int]$b.BatteryStatus)) {
            $sec.pairs['Status'] = $statusMap[[int]$b.BatteryStatus]
        }
        if ($null -ne $b.Chemistry -and $chemMap.ContainsKey([int]$b.Chemistry)) {
            $sec.pairs['Chemistry'] = $chemMap[[int]$b.Chemistry]
        }
        if ($b.DesignVoltage -and [double]$b.DesignVoltage -gt 0) { $sec.pairs['Design voltage'] = '{0:N1} V' -f ([double]$b.DesignVoltage / 1000) }
    }

    $dCap = $null
    if ($designed) { $dCap = [double]@($designed)[0].DesignedCapacity }
    $fCap = $null
    if ($fullCap) { $fCap = [double]@($fullCap)[0].FullChargedCapacity }

    if ($dCap -and $dCap -gt 0) { $sec.pairs['Design capacity'] = '{0:N0} mWh' -f $dCap }
    if ($fCap -and $fCap -gt 0) { $sec.pairs['Full charge capacity'] = '{0:N0} mWh' -f $fCap }
    if ($dCap -and $dCap -gt 0 -and $fCap -and $fCap -gt 0) {
        $health = ($fCap / $dCap) * 100
        $sec.pairs['Battery health'] = '{0:N1} %' -f $health
        $sec.summary['Battery'] = '{0:N0} % health' -f $health
    }
    if ($cycles) {
        $cc = @($cycles)[0].CycleCount
        if ($null -ne $cc) { $sec.pairs['Charge cycles'] = $cc }
    }

    $sec.widgets['charge'] = $null
    if ($bats.Count -gt 0 -and $null -ne $bats[0].EstimatedChargeRemaining) { $sec.widgets['charge'] = [int]$bats[0].EstimatedChargeRemaining }
    $sec.widgets['health'] = $null
    if ($dCap -and $fCap -and $dCap -gt 0) { $sec.widgets['health'] = [Math]::Round(($fCap / $dCap) * 100, 1) }
    $sec.widgets['status'] = $sec.pairs['Status']
    $sec.widgets['cycles'] = $null
    if ($cycles) {
        $cc2 = @($cycles)[0].CycleCount
        if ($null -ne $cc2) { $sec.widgets['cycles'] = $cc2 }
    }
    $subParts = @()
    if ($null -ne $sec.widgets['charge']) { $subParts += ('{0}% charge' -f $sec.widgets['charge']) }
    if ($null -ne $sec.widgets['health']) { $subParts += ('{0:N1}% health' -f $sec.widgets['health']) }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }

    if ($sec.pairs['Battery health'] -and $fCap -and $dCap) {
        $h = ($fCap / $dCap) * 100
        if ($h -lt 60) { [void]$sec.notes.Add('Battery health is below 60 % - replacement is worth considering.') }
        elseif ($h -lt 80) { [void]$sec.notes.Add('Battery health is below 80 % - degradation is noticeable.') }
    }
    if (-not $Script:IsAdmin) { [void]$sec.notes.Add('Some battery details (design/full capacity, cycle count) can require an elevated run on certain systems.') }
    return $sec
}

function Read-Security {
    $sec = ConvertTo-Section 'Security'

    # TPM
    $tpm = Invoke-Safe { Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop }
    if ($tpm) {
        $sec.pairs['TPM present'] = 'Yes'
        if ($tpm.SpecVersion) { $sec.pairs['TPM spec version'] = ([string]$tpm.SpecVersion).Split(',')[0].Trim() }
        $en = 'Disabled'; if ($tpm.IsEnabled_InitialValue -or $tpm.IsEnabled) { $en = 'Enabled' }
        $sec.pairs['TPM enabled'] = $en
        $ac = 'Disabled'; if ($tpm.IsActivated_InitialValue -or $tpm.IsActivated) { $ac = 'Enabled' }
        $sec.pairs['TPM activated'] = $ac
        if ($tpm.ManufacturerIdTxt) { $sec.pairs['TPM manufacturer'] = ([string]$tpm.ManufacturerIdTxt).Trim() }
    } else {
        $sec.pairs['TPM present'] = 'No / not readable'
    }

    # Firmware mode
    $firmware = 'Unknown'
    $sb = $null
    if ($env:firmware_type) { $firmware = $env:firmware_type }
    $sbResult = Invoke-Safe { Confirm-SecureBootUEFI -ErrorAction Stop }
    if ($null -ne $sbResult) {
        $firmware = 'UEFI'
        $sb = $sbResult
    } else {
        $efi = @(Invoke-Safe { Get-CimInstance -ClassName Win32_DiskPartition -Filter "Type LIKE '%EFI%' OR Type LIKE '%GPT%'" -ErrorAction Stop } @())
        if ($efi.Count -gt 0) { $firmware = 'UEFI (GPT disk layout)' }
        elseif ($env:firmware_type -eq 'Legacy') { $firmware = 'Legacy BIOS' }
    }
    $sec.pairs['Firmware mode'] = $firmware
    if ($null -ne $sb) {
        $sbText = 'Disabled'
        if ($sb) { $sbText = 'Enabled' }
        $sec.pairs['Secure Boot'] = $sbText
    } else {
        $sec.pairs['Secure Boot'] = 'Not available (Legacy BIOS or permission denied)'
    }

    # Defender
    $mp = Invoke-Safe { Get-MpComputerStatus -ErrorAction Stop }
    if ($mp) {
        $rt = 'Disabled'; if ($mp.RealTimeProtectionEnabled) { $rt = 'Enabled' }
        $sec.pairs['Defender real-time protection'] = $rt
        $am = 'Disabled'; if ($mp.AMServiceEnabled) { $am = 'Enabled' }
        $sec.pairs['Defender service'] = $am
        if ($mp.AntivirusSignatureVersion) { $sec.pairs['Defender signature version'] = $mp.AntivirusSignatureVersion }
        if ($mp.AntivirusSignatureLastUpdated) { $sec.pairs['Signatures updated'] = Format-Date $mp.AntivirusSignatureLastUpdated }
        if ($mp.PSObject.Properties['IsTamperProtected'] -and $null -ne $mp.IsTamperProtected) {
            $tp = 'Disabled'; if ($mp.IsTamperProtected) { $tp = 'Enabled' }
            $sec.pairs['Tamper protection'] = $tp
        }
    } else {
        [void]$sec.notes.Add('Windows Defender status could not be read (the Defender module may be unavailable or access was denied).')
    }

    # Registered AV products
    $avs = @(Invoke-Safe { Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop } @())
    $avRows = @()
    foreach ($av in $avs) {
        $stateText = $null
        if ($null -ne $av.productState) {
            $state = [int]$av.productState
            if (($state -band 0x1000) -ne 0) { $stateText = 'Enabled' } else { $stateText = 'Disabled' }
        }
        $avRows += [ordered]@{
            'Product' = $av.displayName
            'State'   = $stateText
            'Path'    = $av.pathToSignedProductExe
        }
    }
    if ($avRows.Count -gt 0) {
        $cols = @(
            [ordered]@{ key = 'Product'; label = 'Product' }
            [ordered]@{ key = 'State'; label = 'State' }
            [ordered]@{ key = 'Path'; label = 'Executable' }
        )
        Add-SectionTable -Section $sec -Title ('Registered security products ({0})' -f $avRows.Count) -Columns $cols -Rows $avRows
    }

    # Firewall
    $fw = @(Invoke-Safe { Get-NetFirewallProfile -ErrorAction Stop } @())
    $fwAllOn = $false
    if ($fw.Count -gt 0) {
        $fwRows = @()
        foreach ($f in $fw) {
            $en = 'No'; if ($f.Enabled) { $en = 'Yes' }
            $fwRows += [ordered]@{
                'Profile'  = [string]$f.Name
                'Enabled'  = $en
                'Inbound'  = [string]$f.DefaultInboundAction
                'Outbound' = [string]$f.DefaultOutboundAction
            }
        }
        $cols = @(
            [ordered]@{ key = 'Profile'; label = 'Firewall profile' }
            [ordered]@{ key = 'Enabled'; label = 'Enabled' }
            [ordered]@{ key = 'Inbound'; label = 'Inbound default' }
            [ordered]@{ key = 'Outbound'; label = 'Outbound default' }
        )
        Add-SectionTable -Section $sec -Title 'Windows Firewall' -Columns $cols -Rows $fwRows
        $fwOn = @($fw | Where-Object { $_.Enabled }).Count
        $fwAllOn = ($fwOn -eq $fw.Count)
        $sec.pairs['Firewall'] = '{0} of {1} profiles enabled' -f $fwOn, $fw.Count
    }

    # BitLocker
    $bl = @(Invoke-Safe { Get-BitLockerVolume -ErrorAction Stop } @())
    if ($bl.Count -gt 0) {
        $blRows = @()
        foreach ($v in $bl) {
            $prot = [string]$v.ProtectionStatus
            if ($prot -eq 'On') { $prot = 'Enabled' }
            elseif ($prot -eq 'Off') { $prot = 'Disabled' }
            $blRows += [ordered]@{
                'Volume'       = $v.MountPoint
                'Status'       = [string]$v.VolumeStatus
                'Protection'   = $prot
                'Encryption'   = ('{0} %' -f $v.EncryptionPercentage)
                'Method'       = [string]$v.EncryptionMethod
            }
        }
        $cols = @(
            [ordered]@{ key = 'Volume'; label = 'Volume' }
            [ordered]@{ key = 'Status'; label = 'Status' }
            [ordered]@{ key = 'Protection'; label = 'Protection' }
            [ordered]@{ key = 'Encryption'; label = 'Encrypted' }
            [ordered]@{ key = 'Method'; label = 'Method' }
        )
        Add-SectionTable -Section $sec -Title 'BitLocker volumes' -Columns $cols -Rows $blRows
    } elseif (-not $Script:IsAdmin) {
        [void]$sec.notes.Add('BitLocker volume status requires running SpecsScanner as Administrator.')
    }

    # Dashboard health checklist
    $checks = New-Object System.Collections.ArrayList
    $tp = [string]$sec.pairs['TPM present']
    $tpmStatus = 'warn'; $tpmDetail = $tp
    if ($tp -match '^Yes') {
        if ($sec.pairs['TPM enabled'] -ne 'Disabled') { $tpmStatus = 'ok' }
        $sp = [string]$sec.pairs['TPM spec version']
        if ($sp) { $tpmDetail = 'Spec {0}' -f $sp }
    }
    [void]$checks.Add(@{ label = 'TPM'; status = $tpmStatus; detail = $tpmDetail; desc = 'Security chip behind Windows Hello and disk encryption. TPM 2.0 is the modern standard.' })

    $sb = [string]$sec.pairs['Secure Boot']
    $sbStatus = 'warn'
    if ($sb -eq 'Enabled') { $sbStatus = 'ok' }
    [void]$checks.Add(@{ label = 'Secure Boot'; status = $sbStatus; detail = $sb; desc = 'Makes Windows refuse to load unsigned boot software, blocking bootkits.' })

    $fm = [string]$sec.pairs['Firmware mode']
    $fmStatus = 'warn'
    if ($fm -match 'UEFI') { $fmStatus = 'ok' }
    [void]$checks.Add(@{ label = 'Firmware'; status = $fmStatus; detail = $fm; desc = 'UEFI is the modern firmware interface; Legacy BIOS lacks Secure Boot support.' })

    $dr = [string]$sec.pairs['Defender real-time protection']
    $drStatus = 'bad'
    if ($dr -eq 'Enabled') { $drStatus = 'ok' }
    [void]$checks.Add(@{ label = 'Defender real-time'; status = $drStatus; detail = $dr; desc = 'Always-on malware scanning built into Windows.' })

    if ($sec.pairs['Tamper protection']) {
        $tt = [string]$sec.pairs['Tamper protection']
        $ttStatus = 'warn'; if ($tt -eq 'Enabled') { $ttStatus = 'ok' }
        [void]$checks.Add(@{ label = 'Tamper protection'; status = $ttStatus; detail = $tt; desc = 'Prevents apps from quietly disabling Defender.' })
    }

    if ($sec.pairs['Firewall']) {
        $fwt = [string]$sec.pairs['Firewall']
        $fwtStatus = 'warn'; if ($fwAllOn) { $fwtStatus = 'ok' }
        [void]$checks.Add(@{ label = 'Firewall'; status = $fwtStatus; detail = $fwt; desc = 'Filters inbound and outbound network traffic.' })
    }

    if ($bl.Count -gt 0) {
        $blOn = @($bl | Where-Object { ([string]$_.ProtectionStatus) -eq 'On' }).Count
        $blStatus = 'warn'
        if ($blOn -gt 0) { $blStatus = 'ok' }
        [void]$checks.Add(@{ label = 'Disk encryption'; status = $blStatus; detail = ('{0} of {1} volumes protected' -f $blOn, $bl.Count); desc = 'BitLocker encrypts disks so data stays private if a drive is removed.' })
    }

    $sec.widgets['checks'] = $checks
    $okCount = @($checks | Where-Object { $_.status -eq 'ok' }).Count
    $sec.subtitle = ('{0} checks / {1} passing' -f $checks.Count, $okCount)
    return $sec
}

function Read-Windows {
    $sec = ConvertTo-Section 'Windows'
    $os = Invoke-Safe { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    $cv = Invoke-Safe { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop }

    if ($os) {
        $sec.pairs['Edition'] = $os.Caption
        $build = [string]$os.BuildNumber
        if ($cv -and $cv.UBR) { $build = '{0}.{1}' -f $build, $cv.UBR }
        $sec.pairs['Version'] = '{0} (build {1})' -f $os.Version, $build
        if ($cv -and $cv.DisplayVersion) { $sec.pairs['Feature update'] = $cv.DisplayVersion }
        $sec.pairs['Architecture'] = $os.OSArchitecture
        $sec.pairs['Install date'] = Format-Date $os.InstallDate
        if ($sec.pairs['Install date']) { $sec.summary['InstallDate'] = $sec.pairs['Install date'] }
        $boot = ConvertTo-DateTime $os.LastBootUpTime
        if ($boot) {
            $sec.pairs['Last boot'] = $boot.ToString('yyyy-MM-dd HH:mm')
            $up = (Get-Date) - $boot
            $upText = '{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes
            $sec.pairs['Uptime'] = $upText
            $sec.summary['Uptime'] = $upText
        }
        $sec.pairs['Registered user'] = $os.RegisteredUser
        $sec.pairs['Registered organization'] = $os.Organization
        $sec.pairs['Windows directory'] = $os.WindowsDirectory
        $sec.summary['OS'] = '{0} (build {1})' -f $os.Caption, $build
    } else {
        [void]$sec.notes.Add('Operating system information could not be read from WMI.')
    }

    # Activation
    $lic = @(Invoke-Safe { Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" -ErrorAction Stop } @())
    $winLic = $lic | Where-Object { $_.Name -match '^Windows' } | Select-Object -First 1
    if (-not $winLic) { $winLic = $lic | Select-Object -First 1 }
    if ($winLic) {
        $licMap = @{ 0 = 'Unlicensed'; 1 = 'Licensed'; 2 = 'OOB grace'; 3 = 'OOT grace'; 4 = 'Non-genuine grace'; 5 = 'Notification'; 6 = 'Extended grace' }
        $licText = 'Unknown'
        if ($licMap.ContainsKey([int]$winLic.LicenseStatus)) { $licText = $licMap[[int]$winLic.LicenseStatus] }
        $sec.pairs['Activation'] = $licText
        if ($winLic.ProductKeyChannel) { $sec.pairs['License channel'] = $winLic.ProductKeyChannel }
    } else {
        $sec.pairs['Activation'] = 'Not readable'
    }

    # Locale / timezone / PowerShell / .NET
    $tz = Invoke-Safe { Get-TimeZone -ErrorAction Stop }
    if ($tz) { $sec.pairs['Time zone'] = '{0} ({1})' -f $tz.DisplayName, $tz.Id }
    $sec.pairs['System locale'] = (Get-Culture).DisplayName
    $sec.pairs['PowerShell version'] = $PSVersionTable.PSVersion.ToString()

    if ($cv) {
        $rel = Invoke-Safe { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop).Release }
        if ($rel) {
            $net = $null
            if ([int]$rel -ge 533320) { $net = '4.8.1 or later' }
            elseif ([int]$rel -ge 528040) { $net = '4.8' }
            elseif ([int]$rel -ge 461808) { $net = '4.7.2' }
            elseif ([int]$rel -ge 461308) { $net = '4.7.1' }
            elseif ([int]$rel -ge 460798) { $net = '4.7' }
            elseif ([int]$rel -ge 394802) { $net = '4.6.2' }
            elseif ([int]$rel -ge 394254) { $net = '4.6.1' }
            elseif ([int]$rel -ge 393295) { $net = '4.6' }
            elseif ([int]$rel -ge 379893) { $net = '4.5.2' }
            if ($net) { $sec.pairs['.NET Framework'] = '{0} (release {1})' -f $net, $rel }
            else { $sec.pairs['.NET Framework'] = 'Release {0}' -f $rel }
        }
    }

    # Recent updates
    $qfe = @(Invoke-Safe { Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop } @())
    if ($qfe.Count -gt 0) {
        $sec.pairs['Installed updates'] = $qfe.Count
        $sorted = $qfe | Sort-Object { ConvertTo-DateTime $_.InstalledOn } -Descending | Select-Object -First 8
        $newestUpd = $sorted | Where-Object { ConvertTo-DateTime $_.InstalledOn } | Select-Object -First 1
        if ($newestUpd) {
            $luDate = Format-Date $newestUpd.InstalledOn 'yyyy-MM-dd'
            $luId = [string]$newestUpd.HotFixID
            $luVal = $luDate
            if ($luId) { $luVal = '{0} ({1})' -f $luDate, $luId }
            $sec.pairs['Last update installed'] = $luVal
            $sec.widgets['lastUpdate'] = $luDate
            $sec.widgets['lastUpdateId'] = $luId
        }
        $uRows = @()
        $updateWidgets = @()
        foreach ($q in $sorted) {
            $uRows += [ordered]@{
                'Update'      = $q.HotFixID
                'Description' = $q.Description
                'Installed'   = Format-Date $q.InstalledOn 'yyyy-MM-dd'
            }
            $updateWidgets += [ordered]@{
                id   = $q.HotFixID
                desc = $q.Description
                date = Format-Date $q.InstalledOn 'yyyy-MM-dd'
            }
        }
        $sec.widgets['updates'] = $updateWidgets
        $cols = @(
            [ordered]@{ key = 'Update'; label = 'Update' }
            [ordered]@{ key = 'Description'; label = 'Description' }
            [ordered]@{ key = 'Installed'; label = 'Installed' }
        )
        Add-SectionTable -Section $sec -Title 'Latest updates (8 most recent)' -Columns $cols -Rows $uRows
    }

    if ($os) {
        $sec.widgets['edition'] = [string]$os.Caption
        $build2 = [string]$os.BuildNumber
        if ($cv -and $cv.UBR) { $build2 = '{0}.{1}' -f $build2, $cv.UBR }
        $sec.widgets['build'] = $build2
    }
    $sec.widgets['activation'] = $sec.pairs['Activation']
    $sec.widgets['updateCount'] = $qfe.Count
    $subParts = @()
    if ($sec.widgets['edition']) { $subParts += [string]$sec.widgets['edition'] }
    if ($sec.widgets['build']) { $subParts += ('build {0}' -f $sec.widgets['build']) }
    if ([string]$sec.pairs['Activation'] -eq 'Licensed') { $subParts += 'activated' }
    if ($subParts.Count -gt 0) { $sec.subtitle = ($subParts -join ' / ') }
    return $sec
}

function Read-Peripheral {
    $sec = ConvertTo-Section 'Peripherals'

    # PnP devices (prefer Get-PnpDevice, fall back to WMI).
    $devices = @(Invoke-Safe { Get-PnpDevice -PresentOnly -ErrorAction Stop } @())
    if ($devices.Count -eq 0) {
        $wmiPnp = @(Invoke-Safe { Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop } @())
        $devices = @($wmiPnp | ForEach-Object {
            [pscustomobject]@{ FriendlyName = $_.Name; Class = $_.PNPClass; Status = $_.Status; InstanceId = $_.DeviceID; Manufacturer = $_.Manufacturer }
        })
    }

    if ($devices.Count -gt 0) {
        $byClass = $devices | Where-Object { $_.Class } | Group-Object -Property Class | Sort-Object Count -Descending
        $classRows = @()
        $classWidgets = @()
        foreach ($g in $byClass) {
            $classRows += [ordered]@{ 'Device class' = $g.Name; 'Count' = $g.Count }
            if ($classWidgets.Count -lt 8) { $classWidgets += [ordered]@{ name = [string]$g.Name; count = [int]$g.Count } }
        }
        $sec.widgets['classes'] = $classWidgets
        $cols = @(
            [ordered]@{ key = 'Device class'; label = 'Device class' }
            [ordered]@{ key = 'Count'; label = 'Count' }
        )
        Add-SectionTable -Section $sec -Title ('Devices by class ({0} total)' -f $devices.Count) -Columns $cols -Rows $classRows

        $interesting = @('Keyboard', 'Mouse', 'USB', 'HIDClass', 'Camera', 'Image', 'Media', 'Bluetooth', 'Biometric', 'SmartCard', 'Monitor')
        $notable = @($devices | Where-Object { $_.Class -in $interesting -and $_.FriendlyName })
        $notableRows = @()
        foreach ($d in ($notable | Select-Object -First 120)) {
            $notableRows += [ordered]@{
                'Device'       = $d.FriendlyName
                'Class'        = $d.Class
                'Status'       = $d.Status
                'Manufacturer' = $d.Manufacturer
            }
        }
        if ($notableRows.Count -gt 0) {
            $cols = @(
                [ordered]@{ key = 'Device'; label = 'Device' }
                [ordered]@{ key = 'Class'; label = 'Class' }
                [ordered]@{ key = 'Status'; label = 'Status' }
                [ordered]@{ key = 'Manufacturer'; label = 'Manufacturer' }
            )
            Add-SectionTable -Section $sec -Title 'Keyboards, mice, USB, cameras, Bluetooth' -Columns $cols -Rows $notableRows
        }
    }

    # USB controllers
    $usbCtl = @(Invoke-Safe { Get-CimInstance -ClassName Win32_USBController -ErrorAction Stop } @())
    if ($usbCtl.Count -gt 0) {
        $rows = @()
        foreach ($u in $usbCtl) {
            $rows += [ordered]@{ 'USB controller' = $u.Name; 'Status' = $u.Status }
        }
        $cols = @(
            [ordered]@{ key = 'USB controller'; label = 'USB controller' }
            [ordered]@{ key = 'Status'; label = 'Status' }
        )
        Add-SectionTable -Section $sec -Title ('USB controllers ({0})' -f $rows.Count) -Columns $cols -Rows $rows
    }

    # Printers
    $printers = @(Invoke-Safe { Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop } @())
    if ($printers.Count -gt 0) {
        $rows = @()
        foreach ($p in $printers) {
            $def = 'No'; if ($p.Default) { $def = 'Yes' }
            $shared = 'No'; if ($p.Shared) { $shared = 'Yes' }
            $net = 'No'; if ($p.Network) { $net = 'Yes' }
            $rows += [ordered]@{
                'Printer'      = $p.Name
                'Driver'       = $p.DriverName
                'Port'         = $p.PortName
                'Default'      = $def
                'Shared'       = $shared
                'Network'      = $net
            }
        }
        $cols = @(
            [ordered]@{ key = 'Printer'; label = 'Printer' }
            [ordered]@{ key = 'Driver'; label = 'Driver' }
            [ordered]@{ key = 'Port'; label = 'Port' }
            [ordered]@{ key = 'Default'; label = 'Default' }
            [ordered]@{ key = 'Shared'; label = 'Shared' }
            [ordered]@{ key = 'Network'; label = 'Network' }
        )
        Add-SectionTable -Section $sec -Title ('Printers ({0})' -f $rows.Count) -Columns $cols -Rows $rows
    }

    $sec.widgets['total'] = $devices.Count
    if ($devices.Count -gt 0) { $sec.subtitle = ('{0} devices detected' -f $devices.Count) }
    return $sec
}

function Read-Software {
    $sec = ConvertTo-Section 'Installed Software'
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = @()
    foreach ($p in $paths) {
        $items = @(Invoke-Safe { Get-ItemProperty -Path $p -ErrorAction Stop } @())
        foreach ($item in $items) {
            if ($item.DisplayName -and -not $item.SystemComponent) {
                $apps += [pscustomobject]@{
                    Name      = [string]$item.DisplayName
                    Version   = [string]$item.DisplayVersion
                    Publisher = [string]$item.Publisher
                    Date      = [string]$item.InstallDate
                }
            }
        }
    }

    $apps = @($apps | Sort-Object Name, Version -Unique)
    if ($apps.Count -eq 0) {
        [void]$sec.notes.Add('No installed software entries were found in the registry uninstall keys.')
        return $sec
    }

    $rows = @()
    foreach ($a in $apps) {
        $date = ConvertTo-InstallDateText $a.Date
        $rows += [ordered]@{
            'Name'         = $a.Name
            'Version'      = $a.Version
            'Publisher'    = $a.Publisher
            'Install date' = $date
        }
    }

    $sec.pairs['Total applications'] = $apps.Count
    $cols = @(
        [ordered]@{ key = 'Name'; label = 'Name' }
        [ordered]@{ key = 'Version'; label = 'Version' }
        [ordered]@{ key = 'Publisher'; label = 'Publisher' }
        [ordered]@{ key = 'Install date'; label = 'Install date' }
    )
    Add-SectionTable -Section $sec -Title ('Applications ({0})' -f $rows.Count) -Columns $cols -Rows $rows
    $sec.widgets['count'] = $apps.Count
    $sec.subtitle = ('{0} applications installed' -f $apps.Count)
    return $sec
}

function Read-Service {
    $sec = ConvertTo-Section 'Services'
    $svcs = @(Invoke-Safe { Get-CimInstance -ClassName Win32_Service -Filter "State='Running'" -ErrorAction Stop } @())
    if ($svcs.Count -eq 0) {
        [void]$sec.notes.Add('No running services could be enumerated.')
        return $sec
    }

    $rows = @()
    foreach ($s in ($svcs | Sort-Object Name)) {
        $rows += [ordered]@{
            'Service'     = $s.Name
            'Display name' = $s.DisplayName
            'Start mode'  = $s.StartMode
            'Account'     = $s.StartName
            'Process ID'  = $s.ProcessId
        }
    }

    $sec.pairs['Running services'] = $rows.Count
    $cols = @(
        [ordered]@{ key = 'Service'; label = 'Service' }
        [ordered]@{ key = 'Display name'; label = 'Display name' }
        [ordered]@{ key = 'Start mode'; label = 'Start mode' }
        [ordered]@{ key = 'Account'; label = 'Account' }
        [ordered]@{ key = 'Process ID'; label = 'PID' }
    )
    Add-SectionTable -Section $sec -Title ('Running services ({0})' -f $rows.Count) -Columns $cols -Rows $rows
    $sec.widgets['count'] = $rows.Count
    $sec.subtitle = ('{0} running' -f $rows.Count)
    return $sec
}

# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------
$Script:TemplateHead = @'
<!DOCTYPE html>
<html lang="en" data-theme="{{THEME}}" data-default-theme="{{DEFTHEME}}" style="--brand:var(--fg-{{BRAND}})">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#1e1e2e">
<meta name="generator" content="SpecsScanner {{VERSION}}">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='%23cba6f7'/><text x='16' y='22' font-size='15' font-weight='bold' text-anchor='middle' fill='%2311111b' font-family='Arial'>SS</text></svg>">
<title>{{TITLE}}</title>
<style>
/* ============================================================
   SpecsScanner report - Catppuccin design system (v2)
   Palette usage follows the official Catppuccin style guide.
   Every text/background pair meets WCAG AA (>= 4.5:1), verified
   programmatically for both themes.
   ============================================================ */
:root, [data-theme="mocha"] {
  --brand:#cba6f7;
  --grad-mid:#89b4fa; --grad-end:#74c7ec; --logo-fg:#11111b;
  --mono:ui-monospace,"Cascadia Mono","Segoe UI Mono",Consolas,"Liberation Mono",monospace;
  --base:#1e1e2e; --mantle:#181825; --crust:#11111b;
  --surface0:#313244; --surface1:#45475a; --surface2:#585b70;
  --overlay0:#6c7086; --overlay1:#7f849c; --overlay2:#9399b2;
  --text:#cdd6f4; --label:#a6adc8; --subtle:#7f849c; --dim:#6c7086; --chip-fg:#bac2de;
  --zebra:rgba(49,50,68,.32); --hover:rgba(69,71,90,.38);
  --shadow1:0 1px 2px rgba(0,0,0,.28); --shadow2:0 12px 32px -14px rgba(0,0,0,.55);
  /* Legible text/icon variants of every accent (raw palette passes on dark). */
  --fg-lavender:#b4befe; --fg-blue:#89b4fa; --fg-sapphire:#74c7ec; --fg-sky:#89dceb;
  --fg-teal:#94e2d5; --fg-green:#a6e3a1; --fg-yellow:#f9e2af; --fg-peach:#fab387;
  --fg-maroon:#eba0ac; --fg-red:#f38ba8; --fg-mauve:#cba6f7; --fg-pink:#f5c2e7;
  --fg-flamingo:#f2cdcd; --fg-rosewater:#f5e0dc;
  --fg-ok:var(--fg-green); --fg-warn:var(--fg-yellow); --fg-bad:var(--fg-red); --fg-info:var(--fg-blue);
  --link:var(--fg-blue);
}
[data-theme="latte"] {
  --brand:#8839ef;
  --grad-mid:#1e66f5; --grad-end:#209fb5; --logo-fg:#ffffff;
  --base:#eff1f5; --mantle:#e6e9ef; --crust:#dce0e8;
  --surface0:#ccd0da; --surface1:#bcc0cc; --surface2:#acb0be;
  --overlay0:#9ca0b0; --overlay1:#8c8fa1; --overlay2:#7c7f93;
  --text:#4c4f69; --label:#5c5f77; --subtle:#64677d; --dim:#6c6f85; --chip-fg:#4c4f69;
  --zebra:rgba(204,208,218,.42); --hover:rgba(188,192,204,.5);
  --shadow1:0 1px 2px rgba(76,79,105,.09); --shadow2:0 12px 32px -14px rgba(76,79,105,.25);
  /* Latte accents darkened to >= 4.5:1 on light panels (computed, not guessed). */
  --fg-lavender:#5665BE; --fg-blue:#1B5CDD; --fg-sapphire:#187788; --fg-sky:#0374A0;
  --fg-teal:#12757A; --fg-green:#307820; --fg-yellow:#915C13; --fg-peach:#B24608;
  --fg-maroon:#C43B47; --fg-red:#C80E36; --fg-mauve:#8839EF; --fg-pink:#984D84;
  --fg-flamingo:#9B5454; --fg-rosewater:#8F5A4E;
  --fg-ok:#26601A; --fg-warn:#7B4E10; --fg-bad:#B20D30; --fg-info:#164CB8;
  --link:#1B5CDD;
}
* { box-sizing:border-box; }
html { scroll-behavior:smooth; }
body { margin:0; background:var(--base); color:var(--text);
  font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,"Noto Sans",sans-serif;
  -webkit-font-smoothing:antialiased; }
a { color:var(--link); text-decoration:none; }
a:hover { text-decoration:underline; }
::selection { background:color-mix(in srgb, var(--overlay2) 30%, transparent); }
:focus-visible { outline:2px solid var(--brand); outline-offset:2px; border-radius:6px; }
* { scrollbar-width:thin; scrollbar-color:var(--surface1) transparent; }
::-webkit-scrollbar { width:10px; height:10px; }
::-webkit-scrollbar-thumb { background:var(--surface1); border-radius:99px; border:2px solid var(--base); }
::-webkit-scrollbar-track { background:transparent; }
.wrap { max-width:1280px; margin:0 auto; padding:0 20px; }
.muted { color:var(--label); }
.dim { color:var(--dim); }
.mono { font-family:var(--mono); font-size:12.5px; }
svg { display:block; }

/* ---------- Top bar ---------- */
.top { position:sticky; top:0; z-index:60; background:color-mix(in srgb, var(--crust) 88%, transparent);
  border-bottom:1px solid var(--surface0); }
@supports (backdrop-filter: blur(6px)) {
  .top { backdrop-filter:blur(12px) saturate(1.5); -webkit-backdrop-filter:blur(12px) saturate(1.5); }
}
.progress { position:absolute; left:0; right:0; bottom:-1px; height:2px; overflow:hidden; }
.progress i { display:block; height:100%; width:0;
  background:linear-gradient(90deg, var(--brand), var(--grad-mid), var(--grad-end)); }
.topbar { display:flex; align-items:center; gap:10px; padding:10px 0; flex-wrap:wrap; }
.brand { display:inline-flex; align-items:center; gap:9px; color:var(--text); text-decoration:none; }
.brand:hover { text-decoration:none; }
.logo { display:grid; place-items:center; width:30px; height:30px; border-radius:9px;
  font-weight:800; font-size:12px; letter-spacing:.3px; color:var(--logo-fg);
  background:linear-gradient(135deg, var(--brand), var(--grad-mid), var(--grad-end)); }
.bname { font-weight:750; font-size:16px; letter-spacing:-.2px; }
.vtag { font-size:10.5px; font-weight:600; color:var(--label); border:1px solid var(--surface1);
  border-radius:999px; padding:1px 8px; }
.hosttag { display:inline-flex; align-items:center; gap:6px; font-size:12px; font-weight:650;
  color:var(--text); background:color-mix(in srgb, var(--surface0) 55%, transparent);
  border:1px solid var(--surface1); border-radius:999px; padding:2.5px 11px; }
.hosttag svg { width:13px; height:13px; color:var(--label); }
.pill { display:inline-flex; align-items:center; gap:6px; font-size:12px; font-weight:600;
  padding:3px 11px; border-radius:999px; white-space:nowrap;
  color:var(--tone, var(--text));
  background:color-mix(in srgb, var(--tone, var(--surface1)) 10%, transparent);
  border:1px solid color-mix(in srgb, var(--tone, var(--surface1)) 30%, transparent); }
.pill svg { width:13px; height:13px; }
.t-ok    { --tone:var(--fg-ok); }
.t-warn  { --tone:var(--fg-warn); }
.t-bad   { --tone:var(--fg-bad); }
.t-info  { --tone:var(--fg-info); }
.t-accent{ --tone:var(--accent, var(--brand)); }
.t-neutral { --tone:var(--label); }
.tools { margin-left:auto; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.searchbox { position:relative; display:flex; align-items:center; }
.searchbox > svg { position:absolute; left:10px; width:14px; height:14px; color:var(--subtle); pointer-events:none; }
.searchbox input { background:var(--base); border:1px solid var(--surface1); color:var(--text);
  border-radius:10px; padding:7px 36px 7px 30px; font:inherit; font-size:13px; width:250px;
  outline:none; transition:border-color .12s ease, box-shadow .12s ease; }
.searchbox input:focus { border-color:var(--brand); box-shadow:0 0 0 3px color-mix(in srgb, var(--brand) 16%, transparent); }
.searchbox kbd { position:absolute; right:9px; font-family:var(--mono); font-size:10.5px;
  color:var(--subtle); border:1px solid var(--surface1); border-bottom-width:2px;
  border-radius:5px; padding:0 5px; pointer-events:none; }
#mcount { font-size:12px; color:var(--label); }
.seg { display:inline-flex; background:var(--base); border:1px solid var(--surface1);
  border-radius:10px; padding:2px; gap:2px; }
.segbtn { display:grid; place-items:center; width:30px; height:26px; border:none; border-radius:8px;
  background:transparent; color:var(--subtle); cursor:pointer; padding:0; }
.segbtn svg { width:14px; height:14px; }
.segbtn:hover { color:var(--text); }
.segbtn[aria-pressed="true"] { background:var(--surface0); color:var(--text); }
.btn { display:inline-flex; align-items:center; gap:7px; background:color-mix(in srgb, var(--surface0) 60%, transparent);
  color:var(--text); border:1px solid var(--surface1); border-radius:10px;
  padding:6.5px 12px; font:inherit; font-size:12.5px; font-weight:600; cursor:pointer; }
.btn svg { width:14px; height:14px; }
.btn:hover { background:var(--surface0); }
.nav { display:flex; gap:5px; overflow-x:auto; padding:0 0 10px; scrollbar-width:none; }
.nav::-webkit-scrollbar { display:none; }
.nav a { color:var(--label); font-size:12.5px; font-weight:600; padding:4px 11px;
  border-radius:999px; white-space:nowrap; text-decoration:none; border:1px solid transparent; }
.nav a:hover { color:var(--text); background:color-mix(in srgb, var(--surface0) 50%, transparent); text-decoration:none; }
.nav a.active { color:var(--text); background:color-mix(in srgb, var(--surface0) 70%, transparent);
  border-color:var(--surface1); box-shadow:inset 0 -2px 0 var(--brand); }

/* ---------- Layout ---------- */
main { padding-top:8px; padding-bottom:40px; }
.empty { display:none; align-items:center; gap:14px; background:var(--mantle); border:1px solid var(--surface0);
  border-radius:14px; padding:20px 22px; margin:18px 0; color:var(--label); }
.empty.show { display:flex; }
.empty svg { width:26px; height:26px; color:var(--subtle); }
.empty b { color:var(--text); display:block; font-size:14px; margin-bottom:2px; }

/* ---------- Hero ---------- */
.hero { display:grid; grid-template-columns:repeat(12, minmax(0,1fr)); gap:16px; margin:18px 0 6px; }
.tile { position:relative; background:var(--mantle); border:1px solid var(--surface0);
  border-radius:16px; padding:18px 20px; transition:border-color .12s ease, transform .12s ease;
  box-shadow:var(--shadow1); }
.tile:hover { border-color:color-mix(in srgb, var(--accent, var(--brand)) 45%, var(--surface0)); transform:translateY(-1px); }
.tile-id { grid-column:span 6; overflow:hidden; }
.tile-id > * { position:relative; z-index:1; }
.tile-id::before { content:""; position:absolute; inset:0; pointer-events:none;
  background:radial-gradient(560px 210px at 0% 0%, color-mix(in srgb, var(--brand) 11%, transparent), transparent 62%),
             radial-gradient(420px 180px at 100% 100%, color-mix(in srgb, var(--grad-end) 8%, transparent), transparent 60%); }
.idtop { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:10px; }
.devbadge { display:inline-flex; align-items:center; gap:7px; font-size:11px; font-weight:700;
  letter-spacing:.05em; text-transform:uppercase; color:var(--fg-info);
  background:color-mix(in srgb, var(--fg-info) 10%, transparent);
  border:1px solid color-mix(in srgb, var(--fg-info) 28%, transparent);
  border-radius:999px; padding:3px 11px; }
.devbadge svg { width:13px; height:13px; }
.tile-id h1 { margin:0 0 6px; font-size:clamp(24px, 3vw, 34px); font-weight:800;
  letter-spacing:-.6px; line-height:1.15; overflow-wrap:anywhere; }
.idsum { margin:0 0 12px; color:var(--label); font-size:13.5px; line-height:1.6; max-width:62ch; }
.idsum b { color:var(--text); font-weight:650; }
.idmeta { display:grid; grid-template-columns:repeat(auto-fit, minmax(190px, 1fr)); gap:5px 20px; }
.mrow { display:flex; gap:8px; font-size:12.5px; align-items:baseline; min-width:0; }
.mk { color:var(--label); flex:none; min-width:72px; }
.mv { font-weight:600; overflow-wrap:anywhere; }

.kpis { grid-column:span 6; display:grid; grid-template-columns:1fr 1fr; gap:16px; }
.kpi { display:flex; flex-direction:column; gap:7px; }
.khead { display:flex; align-items:center; gap:9px; }
.kicon { display:grid; place-items:center; width:30px; height:30px; border-radius:9px; flex:none;
  color:var(--accent); background:color-mix(in srgb, var(--accent) 12%, transparent);
  border:1px solid color-mix(in srgb, var(--accent) 25%, transparent); }
.kicon svg { width:16px; height:16px; }
.klabel { font-size:10.5px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:var(--label); }
.kvalue { font-size:16px; font-weight:750; line-height:1.3; overflow-wrap:anywhere; }
.ksub { font-size:12px; color:var(--label); }
.krow { display:flex; align-items:center; gap:14px; min-width:0; }
.krow > div { min-width:0; }
.barline { display:flex; flex-direction:column; gap:5px; margin-top:2px; }
.bar { height:8px; border-radius:999px; background:var(--surface0); overflow:hidden; }
.bar i { display:block; height:100%; border-radius:999px; background:var(--tone, var(--accent, var(--brand))); }
.barlegend { display:flex; justify-content:space-between; gap:10px; font-size:11px; color:var(--label); }

.ring { width:92px; height:92px; flex:none; }
.ring circle { fill:none; stroke-width:8; }
.ring .ringbg { stroke:color-mix(in srgb, var(--surface0) 75%, transparent); }
.ring .ringfg { stroke:var(--tone, var(--accent, var(--brand))); stroke-linecap:round;
  transform:rotate(-90deg); transform-origin:50% 50%; }
.ring text { fill:var(--text); font-size:19px; font-weight:750; text-anchor:middle; }

.health { grid-column:span 12; display:flex; flex-wrap:wrap; align-items:center; gap:8px; padding:2px 2px 0; }
.health .hh { font-size:10.5px; font-weight:700; letter-spacing:.1em; text-transform:uppercase;
  color:var(--label); margin-right:4px; }

/* ---------- Banners / notes ---------- */
.banner { display:flex; gap:12px; align-items:flex-start; background:var(--mantle); border:1px solid var(--surface0);
  border-left:4px solid var(--fg-info); border-radius:14px; padding:14px 18px; margin:16px 0 2px; }
.banner.warn { border-left-color:var(--fg-warn); }
.banner .bi { color:var(--fg-info); flex:none; margin-top:2px; }
.banner.warn .bi { color:var(--fg-warn); }
.banner strong { font-size:13px; }
.banner ul { margin:7px 0 0; padding-left:18px; }
.banner li { margin:3px 0; font-size:13px; color:var(--label); }
.note { display:flex; gap:10px; align-items:flex-start; border-left:3px solid var(--fg-warn);
  background:color-mix(in srgb, var(--fg-warn) 8%, transparent);
  padding:10px 13px; border-radius:0 10px 10px 0; font-size:13px; margin:10px 0 14px; color:var(--text); }
.note .ni { color:var(--fg-warn); flex:none; margin-top:1px; }
.note svg, .banner svg { width:15px; height:15px; }

/* ---------- Sections ---------- */
details.card { background:var(--mantle); border:1px solid var(--surface0); border-radius:14px;
  margin:14px 0; overflow:hidden; box-shadow:var(--shadow1); }
details.card > summary { display:flex; align-items:center; gap:13px; padding:13px 18px;
  cursor:pointer; list-style:none; user-select:none; }
details.card > summary::-webkit-details-marker { display:none; }
.secc { display:grid; place-items:center; width:36px; height:36px; border-radius:11px; flex:none;
  color:var(--accent); background:color-mix(in srgb, var(--accent) 12%, transparent);
  border:1px solid color-mix(in srgb, var(--accent) 25%, transparent); }
.secc svg { width:19px; height:19px; }
.sect { display:flex; flex-direction:column; gap:1px; min-width:0; }
.sect h2 { margin:0; font-size:16.5px; font-weight:700; letter-spacing:-.2px; }
.secsub { font-size:12px; color:var(--label); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:52vw; }
summary .right { margin-left:auto; display:flex; align-items:center; gap:10px; }
.chip { font-size:11px; font-weight:600; color:var(--chip-fg);
  background:color-mix(in srgb, var(--surface0) 75%, transparent);
  border:1px solid var(--surface1); border-radius:999px; padding:2.5px 10px; white-space:nowrap; }
.chev { display:grid; place-items:center; width:22px; height:22px; color:var(--label);
  transition:transform .18s ease; }
.chev svg { width:15px; height:15px; }
details[open] .chev { transform:rotate(90deg); }
.sec-body { padding:2px 18px 18px; }

/* ---------- Widgets ---------- */
.wrow { display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:12px; margin:12px 0 2px; }
.stat { border:1px solid var(--surface0); border-radius:12px; padding:12px 14px;
  background:color-mix(in srgb, var(--surface0) 22%, transparent); }
.sicon { color:var(--accent); margin-bottom:7px; }
.sicon svg { width:16px; height:16px; }
.slabel { font-size:10.5px; font-weight:700; letter-spacing:.09em; text-transform:uppercase; color:var(--label); }
.svalue { font-size:15px; font-weight:750; margin-top:3px; overflow-wrap:anywhere; }
.ssub { font-size:11.5px; color:var(--label); margin-top:2px; }
.stat .barline { margin-top:8px; }

.dcard, .vcard, .ccard, .mcard { border:1px solid var(--surface0); border-radius:12px;
  padding:13px 14px; background:color-mix(in srgb, var(--surface0) 18%, transparent);
  display:flex; flex-direction:column; gap:9px; min-width:0; }
.dchead { display:flex; align-items:center; gap:9px; min-width:0; }
.dcicon { display:grid; place-items:center; width:30px; height:30px; border-radius:9px; flex:none;
  color:var(--accent); background:color-mix(in srgb, var(--accent) 12%, transparent); }
.dcicon svg { width:16px; height:16px; }
.dcname { font-weight:700; font-size:13px; overflow-wrap:anywhere; min-width:0; }
.dcsize { font-size:11.5px; color:var(--label); }
.dchead .pill { margin-left:auto; font-size:11px; padding:2px 9px; }
.dmeta { display:grid; grid-template-columns:repeat(3, 1fr); gap:6px 10px; }
.dmeta > div { min-width:0; }
.dmk { font-size:10px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; color:var(--label); }
.dmv { font-size:12.5px; font-weight:650; margin-top:1px; overflow-wrap:anywhere; }

.ledrow { display:flex; align-items:center; gap:9px; }
.led { width:9px; height:9px; border-radius:50%; flex:none; background:var(--tone, var(--label));
  box-shadow:0 0 0 3.5px color-mix(in srgb, var(--tone, var(--label)) 18%, transparent); }
.led.ok { box-shadow:0 0 0 3px color-mix(in srgb, var(--fg-ok) 18%, transparent); }
.cmeta { display:grid; gap:5px; }
.crow { display:flex; gap:9px; font-size:12px; align-items:baseline; min-width:0; }
.ck { color:var(--label); flex:none; min-width:58px; }
.cv { font-weight:600; overflow-wrap:anywhere; }

.checks { display:grid; grid-template-columns:repeat(auto-fit, minmax(270px, 1fr)); gap:12px; margin:12px 0 2px; }
.check { display:flex; gap:11px; align-items:flex-start; border:1px solid var(--surface0);
  border-radius:12px; padding:12px 14px; background:color-mix(in srgb, var(--surface0) 18%, transparent); }
.cicon { display:grid; place-items:center; width:32px; height:32px; border-radius:10px; flex:none;
  color:var(--tone); background:color-mix(in srgb, var(--tone) 12%, transparent);
  border:1px solid color-mix(in srgb, var(--tone) 28%, transparent); }
.cicon svg { width:16px; height:16px; }
.cbody { min-width:0; flex:1; }
.cname { font-weight:700; font-size:13px; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.cname .pill { font-size:10.5px; padding:1.5px 8px; }
.cdesc { font-size:11.5px; color:var(--label); margin-top:3px; }

.tl { position:relative; margin:14px 0 4px; padding-left:20px; }
.tl::before { content:""; position:absolute; left:6px; top:8px; bottom:8px; width:2px;
  background:color-mix(in srgb, var(--surface1) 65%, transparent); border-radius:99px; }
.tli { position:relative; padding:0 0 13px 6px; }
.tli:last-child { padding-bottom:2px; }
.tli::before { content:""; position:absolute; left:-18px; top:5px; width:9px; height:9px; border-radius:50%;
  background:var(--accent); box-shadow:0 0 0 3px var(--mantle); }
.tlhead { display:flex; gap:9px; align-items:baseline; flex-wrap:wrap; }
.tlname { font-weight:700; font-size:13px; }
.tldate { font-size:11.5px; color:var(--label); }
.tldesc { font-size:12px; color:var(--label); margin-top:2px; }

/* ---------- Tables ---------- */
.table-wrap { margin:16px 0 6px; }
.table-wrap h3 { margin:0 0 8px; font-size:11.5px; font-weight:700; color:var(--label);
  text-transform:uppercase; letter-spacing:.09em; }
.scroll { overflow:auto; max-height:560px; border:1px solid var(--surface0); border-radius:12px; }
table { width:100%; border-collapse:separate; border-spacing:0; font-size:13px; }
th { text-align:left; font-size:10.5px; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
  color:var(--label); padding:9px 12px; border-bottom:1px solid var(--surface0); white-space:nowrap; }
.scroll thead th { position:sticky; top:0; z-index:2; background:var(--crust); }
th.sortable { cursor:pointer; user-select:none; }
th.sortable:hover { color:var(--text); }
th[aria-sort="ascending"]::after { content:" \25B2"; color:var(--brand); font-size:9px; }
th[aria-sort="descending"]::after { content:" \25BC"; color:var(--brand); font-size:9px; }
td { padding:7.5px 12px; border-bottom:1px solid color-mix(in srgb, var(--surface0) 55%, transparent);
  vertical-align:top; overflow-wrap:anywhere; }
tbody tr:nth-child(even) td { background:var(--zebra); }
tbody tr:last-child td { border-bottom:none; }
tbody tr:hover td { background:var(--hover); }
td.num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
td.mono { font-family:var(--mono); font-size:12px; }
td.copyable { cursor:pointer; }
td.copyable:hover { text-decoration:underline dotted; text-underline-offset:3px; }
td.copied { animation:flashrow .7s ease; }
@keyframes flashrow { 0% { background:color-mix(in srgb, var(--fg-ok) 22%, transparent); } 100% { background:transparent; } }
table.kv { border:1px solid var(--surface0); border-radius:12px; overflow:hidden; }
table.kv th { width:300px; min-width:190px; text-transform:none; font-size:13px; letter-spacing:0;
  font-weight:600; color:var(--label); background:color-mix(in srgb, var(--surface0) 32%, transparent);
  white-space:normal; }
table.kv td { background:transparent !important; }
table.kv tr:hover td { background:var(--hover); }
table.kv tr:last-child th, table.kv tr:last-child td { border-bottom:none; }
.st-ok   { color:var(--fg-ok); font-weight:650; }
.st-warn { color:var(--fg-warn); font-weight:650; }
.st-bad  { color:var(--fg-bad); font-weight:650; }
.hidden-row { display:none; }
.hide { display:none !important; }

/* ---------- Footer + controls ---------- */
footer { border-top:1px solid var(--surface0); color:var(--label); font-size:12.5px;
  padding:22px 0 32px; margin-top:26px; }
footer p { margin:4px 0; }
footer .footlinks { display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin-top:6px; }
#up { position:fixed; right:20px; bottom:20px; width:40px; height:40px; border-radius:12px;
  border:1px solid var(--surface1); background:var(--mantle); color:var(--text);
  cursor:pointer; display:none; place-items:center; box-shadow:var(--shadow2); z-index:70; }
#up svg { width:16px; height:16px; }
#up.show { display:grid; }
.toast { position:fixed; left:50%; bottom:26px; transform:translateX(-50%) translateY(8px);
  background:var(--crust); color:var(--text); border:1px solid var(--surface1); border-radius:11px;
  padding:9px 16px; font-size:13px; box-shadow:var(--shadow2); z-index:90; opacity:0;
  pointer-events:none; transition:opacity .18s ease, transform .18s ease; max-width:80vw; }
.toast.show { opacity:1; transform:translateX(-50%); }

/* ---------- Responsive ---------- */
@media (max-width:1120px) {
  .tile-id { grid-column:span 12; }
  .kpis { grid-column:span 12; }
}
@media (max-width:760px) {
  .kpis { grid-template-columns:1fr; }
  .tools { margin-left:0; width:100%; }
  .searchbox { flex:1; }
  .searchbox input { width:100%; }
  table.kv th { width:auto; min-width:120px; }
  .secsub { max-width:none; }
  .dmeta { grid-template-columns:repeat(2, 1fr); }
  .idsum { max-width:none; }
}

/* ---------- Print ---------- */
@media print {
  html[data-theme] {
    --base:#ffffff; --mantle:#ffffff; --crust:#f4f4f6;
    --surface0:#d9dbe2; --surface1:#c6cad3; --surface2:#b8bcc8;
    --text:#2b2d3a; --label:#4c4f69; --subtle:#5c5f77; --dim:#6c6f85; --chip-fg:#4c4f69;
    --zebra:rgba(220,222,229,.35); --hover:rgba(204,208,218,.4);
    --shadow1:none; --shadow2:none;
  }
  .top .tools, .nav, #up, .progress, .toast { display:none !important; }
  .top { position:static; background:#fff; border-bottom:1px solid #d9dbe2; }
  .tile-id::before { display:none; }
  details.card { break-inside:avoid-page; margin:10px 0; }
  .scroll { max-height:none; overflow:visible; }
  .scroll thead th { position:static; }
  a { color:#2b2d3a; }
  body { background:#fff; }
}

/* ---------- Accessibility fallbacks ---------- */
@media (prefers-reduced-motion: reduce) {
  * { animation:none !important; transition:none !important; }
  html { scroll-behavior:auto; }
}
@media (forced-colors: active) {
  .tile, details.card, .stat, .check, .scroll, table.kv, .dcard, .vcard, .ccard, .mcard { border-color:CanvasText; }
  .pill, .devbadge, .chip, .secc, .kicon, .cicon, .dcicon, .note, .banner { border-color:CanvasText; color:CanvasText; }
  .bar i, .led, .tli::before, .logo { background:CanvasText; }
  .ring .ringfg { stroke:CanvasText; }
  .ring .ringbg { stroke:Canvas; }
}
</style>
</head>
<body>
<header class="top">
  <div class="progress" aria-hidden="true"><i id="prog"></i></div>
  <div class="wrap topbar">
    <a class="brand" href="#overview">
      <span class="logo">SS</span>
      <span class="bname">SpecsScanner</span>
      <span class="vtag">v{{VERSION}}</span>
    </a>
    <span class="hosttag">{{ICON_HOST}}{{HOST}}</span>
    <span class="pill {{ADMINPILL}}">{{ADMINTAG}}</span>
    {{REDACTCHIP}}
    <div class="tools">
      <div class="searchbox">
        {{ICON_SEARCH}}
        <input id="search" type="search" placeholder="Search everything" autocomplete="off" spellcheck="false" aria-label="Search the report">
        <kbd>/</kbd>
      </div>
      <span id="mcount" aria-live="polite"></span>
      <div class="seg" role="group" aria-label="Report theme">
        <button id="th-auto" class="segbtn" type="button" title="Follow system theme" aria-pressed="false">{{ICON_AUTO}}</button>
        <button id="th-latte" class="segbtn" type="button" title="Latte (light)" aria-pressed="false">{{ICON_SUN}}</button>
        <button id="th-mocha" class="segbtn" type="button" title="Mocha (dark)" aria-pressed="false">{{ICON_MOON}}</button>
      </div>
      <button id="togglebtn" class="btn" type="button">{{ICON_FOLD}}<span>Collapse all</span></button>
      <button class="btn" type="button" onclick="window.print()">{{ICON_PRINT}}<span>Print</span></button>
    </div>
  </div>
  <nav class="wrap nav" id="nav" aria-label="Report sections">{{NAV}}</nav>
</header>
<main class="wrap" id="main">
<div id="emptystate" class="empty">{{ICON_SEARCH}}<div><b>No matches</b>Nothing in the report matches that search term.</div></div>
{{HERO}}
{{BANNER}}
'@
$Script:TemplateFoot = @'
</main>
<footer>
  <div class="wrap">
    <p>Generated by <strong>SpecsScanner</strong> v{{VERSION}} on {{DATE}} in {{ELAPSED}} s &middot; {{SECTIONS}} sections &middot; 100% local scan &mdash; nothing ever leaves this machine.</p>
    <p class="muted">Catppuccin Mocha &middot; Latte &middot; Auto &middot; Scanned with PowerShell {{PSV}}{{REDACTNOTE}}</p>
    <p class="footlinks">
      <a href="https://github.com/KingStan0/SpecsScanner" target="_blank" rel="noopener">SpecsScanner on GitHub</a>
      <span class="muted">MIT licensed &middot; free and open source</span>
    </p>
  </div>
</footer>
<button id="up" type="button" title="Back to top">{{ICON_UP}}</button>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>
(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var mqLight = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  var themeMeta = document.querySelector('meta[name="theme-color"]');
  var THEME_KEY = "specsscanner-theme";

  /* ---------- Theme: Mocha / Latte / Auto ---------- */
  function resolvedTheme(pref) {
    if (pref === "auto") { return (mqLight && mqLight.matches) ? "latte" : "mocha"; }
    return pref;
  }
  function markThemeButtons(pref) {
    ["auto", "latte", "mocha"].forEach(function (t) {
      var b = document.getElementById("th-" + t);
      if (b) { b.setAttribute("aria-pressed", t === pref ? "true" : "false"); }
    });
  }
  function applyTheme(pref, animate) {
    var theme = resolvedTheme(pref);
    var swap = function () {
      root.setAttribute("data-theme", theme);
      root.setAttribute("data-theme-pref", pref);
      if (themeMeta) { themeMeta.setAttribute("content", theme === "latte" ? "#eff1f5" : "#1e1e2e"); }
    };
    if (animate && !reduce && document.startViewTransition) { document.startViewTransition(swap); }
    else { swap(); }
    markThemeButtons(pref);
    try {
      if (pref === "auto") { localStorage.removeItem(THEME_KEY); }
      else { localStorage.setItem(THEME_KEY, pref); }
    } catch (e) { }
  }
  var defPref = root.getAttribute("data-default-theme") || "mocha";
  var pref = defPref;
  try { pref = localStorage.getItem(THEME_KEY) || defPref; } catch (e) { pref = defPref; }
  if (["auto", "latte", "mocha"].indexOf(pref) === -1) { pref = defPref; }
  applyTheme(pref, false);
  ["auto", "latte", "mocha"].forEach(function (t) {
    var b = document.getElementById("th-" + t);
    if (b) { b.addEventListener("click", function () { applyTheme(t, true); }); }
  });
  if (mqLight && mqLight.addEventListener) {
    mqLight.addEventListener("change", function () {
      if (root.getAttribute("data-theme-pref") === "auto") { applyTheme("auto", false); }
    });
  }

  /* ---------- Toast ---------- */
  var toastEl = document.getElementById("toast");
  var toastTimer = null;
  function toast(msg) {
    if (!toastEl) { return; }
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    if (toastTimer) { clearTimeout(toastTimer); }
    toastTimer = setTimeout(function () { toastEl.classList.remove("show"); }, 1600);
  }

  /* ---------- Click to copy ---------- */
  function legacyCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { }
    document.body.removeChild(ta);
  }
  document.querySelectorAll(".copyable").forEach(function (el) {
    el.title = "Click to copy";
    el.addEventListener("click", function () {
      var text = el.getAttribute("data-copy") || el.textContent.trim();
      function done() {
        el.classList.add("copied");
        setTimeout(function () { el.classList.remove("copied"); }, 750);
        toast("Copied to clipboard");
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text); done(); });
      } else { legacyCopy(text); done(); }
    });
  });

  /* ---------- Table sorting ---------- */
  document.querySelectorAll(".scroll table").forEach(function (tbl) {
    var ths = Array.prototype.slice.call(tbl.querySelectorAll("thead th"));
    ths.forEach(function (th, idx) {
      th.classList.add("sortable");
      th.setAttribute("tabindex", "0");
      th.setAttribute("role", "button");
      function cellValue(tr) {
        var td = tr.children[idx];
        if (!td) { return ""; }
        var v = td.getAttribute("data-v");
        return v !== null ? v : td.textContent.trim();
      }
      function sortRows() {
        var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
        ths.forEach(function (o) { o.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", dir);
        var tbody = tbl.querySelector("tbody");
        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        var numRe = /^[+-]?(\d+\.?\d*|\.\d+)$/;
        var numeric = rows.every(function (tr) {
          var v = cellValue(tr).replace(/,/g, "");
          return v === "" || numRe.test(v);
        });
        rows.sort(function (a, b) {
          var va = cellValue(a), vb = cellValue(b);
          if (numeric) {
            va = va === "" ? -Infinity : parseFloat(va.replace(/,/g, ""));
            vb = vb === "" ? -Infinity : parseFloat(vb.replace(/,/g, ""));
            return va === vb ? 0 : (va < vb ? -1 : 1);
          }
          va = va.toLowerCase(); vb = vb.toLowerCase();
          return va === vb ? 0 : (va < vb ? -1 : 1);
        });
        if (dir === "descending") { rows.reverse(); }
        rows.forEach(function (tr) { tbody.appendChild(tr); });
      }
      th.addEventListener("click", sortRows);
      th.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sortRows(); }
      });
    });
  });

  /* ---------- Search (press / to focus, Esc to clear) ---------- */
  var search = document.getElementById("search");
  var mcount = document.getElementById("mcount");
  var emptyState = document.getElementById("emptystate");
  function runSearch() {
    var q = search.value.trim().toLowerCase();
    var rowsFound = 0;
    document.querySelectorAll(".scroll").forEach(function (sc) {
      var tbl = sc.querySelector("table");
      if (!tbl) { return; }
      var shown = 0;
      tbl.querySelectorAll("tbody tr").forEach(function (tr) {
        var match = q === "" || tr.textContent.toLowerCase().indexOf(q) !== -1;
        tr.classList.toggle("hidden-row", !match);
        if (match) { shown++; }
      });
      var wrap = sc.closest(".table-wrap") || sc;
      wrap.classList.toggle("hide", q !== "" && shown === 0);
      rowsFound += shown;
    });
    var visibleSections = 0;
    document.querySelectorAll("details.card").forEach(function (sec) {
      var noRows = sec.querySelectorAll("tbody tr:not(.hidden-row)").length === 0;
      var textHit = q !== "" && sec.textContent.toLowerCase().indexOf(q) !== -1;
      var hide = q !== "" && noRows && !textHit;
      sec.classList.toggle("hide", hide);
      if (q !== "" && !hide) { sec.open = true; visibleSections++; }
    });
    if (mcount) {
      if (q === "") { mcount.textContent = ""; }
      else if (rowsFound === 1) { mcount.textContent = "1 matching row"; }
      else { mcount.textContent = rowsFound + " matching rows"; }
    }
    if (emptyState) { emptyState.classList.toggle("show", q !== "" && visibleSections === 0); }
  }
  if (search) {
    search.addEventListener("input", runSearch);
    document.addEventListener("keydown", function (e) {
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) {
        e.preventDefault();
        search.focus();
        search.select();
      } else if (e.key === "Escape" && document.activeElement === search) {
        search.value = "";
        runSearch();
        search.blur();
      }
    });
  }

  /* ---------- Collapse / expand all ---------- */
  var toggleBtn = document.getElementById("togglebtn");
  var toggleLabel = toggleBtn ? toggleBtn.querySelector("span") : null;
  function setAll(open) {
    document.querySelectorAll("details.card").forEach(function (d) { d.open = open; });
    if (toggleLabel) { toggleLabel.textContent = open ? "Collapse all" : "Expand all"; }
  }
  if (toggleBtn) {
    toggleBtn.addEventListener("click", function () {
      setAll(document.querySelector("details.card:not([open])") !== null);
    });
  }

  /* ---------- Scroll progress + back to top ---------- */
  var prog = document.getElementById("prog");
  var up = document.getElementById("up");
  function onScroll() {
    var doc = document.documentElement;
    var max = doc.scrollHeight - window.innerHeight;
    var pct = max > 0 ? (window.scrollY / max) * 100 : 0;
    if (prog) { prog.style.width = pct.toFixed(2) + "%"; }
    if (up) { up.classList.toggle("show", window.scrollY > 700); }
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });
  if (up) {
    up.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
    });
  }
  onScroll();

  /* ---------- Scroll spy navigation ---------- */
  var navLinks = {};
  document.querySelectorAll("#nav a").forEach(function (a) {
    navLinks[a.getAttribute("href")] = a;
  });
  if ("IntersectionObserver" in window) {
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) { return; }
        Object.keys(navLinks).forEach(function (k) { navLinks[k].classList.remove("active"); });
        var link = navLinks["#" + en.target.id];
        if (link) { link.classList.add("active"); }
      });
    }, { rootMargin: "-25% 0px -65% 0px" });
    document.querySelectorAll("main section, main details.card").forEach(function (s) { obs.observe(s); });
  }

  /* ---------- Print: expand everything ---------- */
  window.addEventListener("beforeprint", function () {
    document.querySelectorAll("details.card").forEach(function (d) { d.open = true; });
  });
})();
</script>
</body>
</html>
'@

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Icons - inline SVG, stroke uses currentColor, sized by CSS
# ---------------------------------------------------------------------------
$Script:Icons = @{
    'search'   = '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>'
    'sun'      = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
    'moon'     = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>'
    'auto'     = '<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" stroke="none"/>'
    'print'    = '<polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>'
    'fold'     = '<polyline points="7 20 12 15 17 20"/><polyline points="7 4 12 9 17 4"/>'
    'chev'     = '<polyline points="9 18 15 12 9 6"/>'
    'up'       = '<line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/>'
    'host'     = '<rect x="5" y="2" width="14" height="20" rx="2"/><line x1="9" y1="6" x2="15" y2="6"/><line x1="9" y1="10" x2="15" y2="10"/><circle cx="12" cy="17" r="1"/>'
    'info'     = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'
    'warn'     = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'
    'ok'       = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
    'bad'      = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'
    'unknown'  = '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>'
    'board'    = '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><circle cx="15.5" cy="8.5" r="1.5"/><circle cx="8.5" cy="15.5" r="1.5"/><circle cx="15.5" cy="15.5" r="1.5"/>'
    'cpu'      = '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>'
    'memory'   = '<rect x="2" y="7" width="20" height="10" rx="1.5"/><line x1="6" y1="10" x2="6" y2="14"/><line x1="10" y1="10" x2="10" y2="14"/><line x1="14" y1="10" x2="14" y2="14"/><line x1="18" y1="10" x2="18" y2="14"/><line x1="5" y1="17" x2="5" y2="20"/><line x1="19" y1="17" x2="19" y2="20"/>'
    'gpu'      = '<rect x="2" y="5" width="20" height="14" rx="2"/><circle cx="9" cy="12" r="3"/><line x1="15" y1="9" x2="19" y2="9"/><line x1="15" y1="12" x2="19" y2="12"/><line x1="15" y1="15" x2="19" y2="15"/><line x1="6" y1="19" x2="6" y2="22"/>'
    'display'  = '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>'
    'disk'     = '<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>'
    'network'  = '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>'
    'audio'    = '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>'
    'battery'  = '<rect x="1" y="6" width="18" height="12" rx="2"/><line x1="23" y1="13" x2="23" y2="11"/>'
    'shield'   = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    'windows'  = '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>'
    'usb'      = '<path d="M12 21v-6"/><path d="M9 3v4"/><path d="M15 3v4"/><path d="M7 7h10v3a5 5 0 0 1-10 0z"/>'
    'package'  = '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>'
    'services' = '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>'
    'clock'    = '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>'
    'calendar' = '<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>'
    'zap'      = '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>'
}

function Get-SsIcon {
    param([string]$Name)
    $path = $null
    if ($Name -and $Script:Icons.ContainsKey($Name)) { $path = $Script:Icons[$Name] }
    if (-not $path) { $path = $Script:Icons['info'] }
    return ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{0}</svg>' -f $path)
}

function Get-ToneVar {
    # Maps a status word to the CSS variable holding its theme-safe color.
    param([string]$Status)
    switch ($Status) {
        'ok'      { return 'var(--fg-ok)' }
        'warn'    { return 'var(--fg-warn)' }
        'bad'     { return 'var(--fg-bad)' }
        'info'    { return 'var(--fg-info)' }
        'neutral' { return 'var(--label)' }
    }
    return 'var(--fg-info)'
}

function Get-ToneFromText {
    param([string]$Value)
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if ($v -eq '') { return 'neutral' }
    if ($v -match 'unhealthy|failed|critical|error|denied') { return 'bad' }
    if ($v -match 'healthy|licensed|activated|^ok$|^on$|^yes$|^enabled$|connected|running|protected|uefi') { return 'ok' }
    if ($v -match 'warning|caution|degraded|disabled|^off$|^no$|legacy|unknown|limited') { return 'warn' }
    return 'neutral'
}

function ConvertTo-HtmlValue {
    # Escaped text, or a dim dash when empty.
    param($Value)
    if ($null -eq $Value -or ([string]$Value).Trim() -eq '') { return '<span class="dim">&mdash;</span>' }
    return (ConvertTo-HtmlText ([string]$Value).Trim())
}

function ConvertTo-HtmlPill {
    param([string]$Tone, [string]$Icon, [string]$Text, [string]$Title)
    $cls = 'pill'
    if ($Tone) { $cls = 'pill t-' + $Tone }
    $iconHtml = ''
    if ($Icon) { $iconHtml = (Get-SsIcon $Icon) }
    $titleAttr = ''
    if ($Title) { $titleAttr = (' title="{0}"' -f (ConvertTo-HtmlText $Title)) }
    return ('<span class="{0}"{1}>{2}{3}</span>' -f $cls, $titleAttr, $iconHtml, (ConvertTo-HtmlText $Text))
}

function ConvertTo-HtmlStat {
    param([string]$Label, [string]$Value, [string]$Sub, [string]$Icon)
    $iconHtml = ''
    if ($Icon) { $iconHtml = ('<div class="sicon">{0}</div>' -f (Get-SsIcon $Icon)) }
    $subHtml = ''
    if (-not [string]::IsNullOrWhiteSpace($Sub)) { $subHtml = ('<div class="ssub">{0}</div>' -f (ConvertTo-HtmlText $Sub)) }
    return ('<div class="stat">{0}<div class="slabel">{1}</div><div class="svalue">{2}</div>{3}</div>' -f $iconHtml, (ConvertTo-HtmlText $Label), (ConvertTo-HtmlValue $Value), $subHtml)
}

function ConvertTo-HtmlMiniCard {
    param([string]$Icon, [string]$Name, [string]$Sub, [string]$Right)
    $iconHtml = ''
    if ($Icon) { $iconHtml = (Get-SsIcon $Icon) }
    $subHtml = ''
    if (-not [string]::IsNullOrWhiteSpace($Sub)) { $subHtml = ('<div class="dcsize">{0}</div>' -f (ConvertTo-HtmlText $Sub)) }
    return ('<div class="mcard"><div class="dchead"><span class="dcicon">{0}</span><div style="min-width:0"><div class="dcname">{1}</div>{2}</div>{3}</div></div>' -f $iconHtml, (ConvertTo-HtmlText $Name), $subHtml, $Right)
}

function ConvertTo-HtmlRing {
    param([double]$Pct, [string]$CenterText, [string]$ToneVar, [string]$AriaLabel)
    if ($Pct -lt 0) { $Pct = 0 }
    if ($Pct -gt 100) { $Pct = 100 }
    $circ = 2 * [Math]::PI * 40
    $dash = [Math]::Round(($Pct / 100.0) * $circ, 1)
    $tone = 'var(--fg-info)'
    if ($ToneVar) { $tone = $ToneVar }
    $label = $AriaLabel
    if (-not $label) { $label = $CenterText }
    return ('<svg class="ring" viewBox="0 0 96 96" role="img" aria-label="{0}"><circle class="ringbg" cx="48" cy="48" r="40"/><circle class="ringfg" cx="48" cy="48" r="40" style="--tone:{1};stroke-dasharray:{2} {3}"/><text x="48" y="54">{4}</text></svg>' -f (ConvertTo-HtmlText $label), $tone, [string]$dash, [string]([Math]::Round($circ, 2)), (ConvertTo-HtmlText $CenterText))
}

function ConvertTo-HtmlBar {
    param([double]$Pct, [string]$ToneVar, [string]$AriaLabel)
    if ($Pct -lt 0) { $Pct = 0 }
    if ($Pct -gt 100) { $Pct = 100 }
    $tone = 'var(--fg-info)'
    if ($ToneVar) { $tone = $ToneVar }
    $w = [Math]::Round($Pct, 1)
    return ('<div class="bar" role="img" aria-label="{0}"><i style="width:{1}%;--tone:{2}"></i></div>' -f (ConvertTo-HtmlText $AriaLabel), [string]$w, $tone)
}

function Get-CellMeta {
    # Decides table-cell presentation: numeric sort key, monospace, copy-to-clipboard.
    param($Value, [string]$ColumnLabel)
    $meta = @{ isNum = $false; dataV = $null; copy = $false; mono = $false }
    if ($null -eq $Value -or $Value -is [array]) { return $meta }
    if ($Value -is [bool]) { return $meta }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $meta }
    if ($s -match '^\d{4}-\d{2}-\d{2}') {
        $meta.isNum = $true
        $meta.dataV = ($s -replace '\D', '')
        return $meta
    }
    if ($s -match '^\d+(\.\d+){2,}$' -and $s.Length -le 40) {
        # Version-like value: pad segments so a plain string sort is semantically correct.
        $pad = $s.Split('.') | ForEach-Object { $_.PadLeft(6, '0') }
        $meta.isNum = $true
        $meta.dataV = ($pad -join '.')
        return $meta
    }
    if ($s -match '^-?[\d][\d,\.]*(\s+[A-Za-z%/\.]+)?$') {
        $meta.isNum = $true
        $meta.dataV = ($s -replace '[^0-9\.\-]', '')
    }
    $sens = '(?i)\b(serial|mac|ipv4|ipv6|uuid|guid|asset|ssid|hostname|computer name|product key)\b'
    if ($ColumnLabel -and ($ColumnLabel -match $sens)) { $meta.copy = $true; $meta.mono = $true }
    if ($s -match '(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$') { $meta.copy = $true; $meta.mono = $true }
    if ($s -match '(?i)^[0-9a-f]{8}-[0-9a-f]{4}-') { $meta.copy = $true; $meta.mono = $true }
    if ($s -match '^(\d{1,3}\.){3}\d{1,3}$') { $meta.copy = $true; $meta.mono = $true }
    return $meta
}

function ConvertTo-HtmlPairTable {
    param($Pairs)
    if ($null -eq $Pairs -or $Pairs.Keys.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table class="kv"><tbody>')
    foreach ($k in $Pairs.Keys) {
        $val = $Pairs[$k]
        $plain = ''
        if ($null -ne $val -and $val -isnot [array] -and $val -isnot [bool]) { $plain = ([string]$val).Trim() }
        $cell = ConvertTo-HtmlCell $val
        $sensLabel = '(?i)\b(serial|mac|ipv4|ipv6|uuid|guid|asset|ssid|hostname|computer name|product key)\b'
        $isSensitive = ($k -match $sensLabel) -or ($plain -match '(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$')
        if ($isSensitive -and $plain -ne '') {
            $cell = ('<span class="copyable mono" data-copy="{0}">{1}</span>' -f (ConvertTo-HtmlText $plain), $cell)
        }
        [void]$sb.AppendFormat('<tr><th>{0}</th><td>{1}</td></tr>', (ConvertTo-HtmlText $k), $cell)
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function ConvertTo-HtmlDataTable {
    param($Table)
    if ($null -eq $Table -or @($Table.rows).Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap">')
    if ($Table.title) { [void]$sb.AppendFormat('<h3>{0}</h3>', (ConvertTo-HtmlText $Table.title)) }
    [void]$sb.Append('<div class="scroll"><table><thead><tr>')
    foreach ($c in $Table.columns) {
        [void]$sb.AppendFormat('<th>{0}</th>', (ConvertTo-HtmlText $c.label))
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Table.rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Table.columns) {
            $val = $null
            if ($row.Contains($c.key)) { $val = $row[$c.key] }
            $cm = Get-CellMeta -Value $val -ColumnLabel ([string]$c.label)
            $classes = @()
            if ($cm.isNum) { $classes += 'num' }
            if ($cm.mono) { $classes += 'mono' }
            if ($cm.copy) { $classes += 'copyable' }
            $attrs = ''
            if ($classes.Count -gt 0) { $attrs += (' class="{0}"' -f ($classes -join ' ')) }
            if ($cm.dataV -and ([string]$cm.dataV) -ne '') { $attrs += (' data-v="{0}"' -f (ConvertTo-HtmlText ([string]$cm.dataV))) }
            if ($cm.copy) {
                $plain = ''
                if ($null -ne $val) { $plain = ([string]$val).Trim() }
                $attrs += (' data-copy="{0}"' -f (ConvertTo-HtmlText $plain))
            }
            [void]$sb.AppendFormat('<td{0}>{1}</td>', $attrs, (ConvertTo-HtmlCell $val))
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div></div>')
    return $sb.ToString()
}

function ConvertTo-HtmlWidget {
    # Visual summary row rendered above a section's tables.
    param([string]$Key, $Section)
    $w = $Section.widgets
    if ($null -eq $w) { return '' }
    $out = ''

    switch ($Key) {
        'System' {
            $tiles = ''
            if ($w['chassis']) { $tiles += (ConvertTo-HtmlStat -Label 'Chassis' -Value ([string]$w['chassis']) -Icon 'host') }
            if (([string]$w['vm']) -match '(?i)^yes') { $tiles += (ConvertTo-HtmlStat -Label 'Virtualized' -Value ([string]$w['vm']) -Icon 'cpu') }
            if ($w['bios']) { $tiles += (ConvertTo-HtmlStat -Label 'Firmware' -Value ([string]$w['bios']) -Icon 'board') }
            if ($w['domain']) { $tiles += (ConvertTo-HtmlStat -Label 'Domain / workgroup' -Value ([string]$w['domain']) -Icon 'network') }
            if ($tiles -ne '') { $out = ('<div class="wrow">{0}</div>' -f $tiles) }
        }
        'CPU' {
            $tiles = ''
            if ($w['cores']) { $tiles += (ConvertTo-HtmlStat -Label 'Cores' -Value ([string]$w['cores']) -Icon 'cpu') }
            if ($w['threads']) { $tiles += (ConvertTo-HtmlStat -Label 'Threads' -Value ([string]$w['threads']) -Icon 'zap') }
            if ($w['clock']) { $tiles += (ConvertTo-HtmlStat -Label 'Max clock' -Value ([string]$w['clock']) -Icon 'clock') }
            $cacheParts = @()
            if ($w['l2']) { $cacheParts += ('L2 ' + [string]$w['l2']) }
            if ($w['l3']) { $cacheParts += ('L3 ' + [string]$w['l3']) }
            if ($cacheParts.Count -gt 0) { $tiles += (ConvertTo-HtmlStat -Label 'Cache' -Value ($cacheParts -join ' / ') -Icon 'memory') }
            if ($tiles -ne '') { $out = ('<div class="wrow">{0}</div>' -f $tiles) }
        }
        'Memory' {
            $row = ''
            $pct = $w['usedPct']
            if ($null -ne $pct) {
                $tone = 'var(--fg-ok)'
                if ($pct -ge 90) { $tone = 'var(--fg-bad)' }
                elseif ($pct -ge 75) { $tone = 'var(--fg-warn)' }
                $freeText = Format-ByteSize $w['freeBytes']
                $totalText = Format-ByteSize $w['totalBytes']
                $ring = ConvertTo-HtmlRing -Pct ([double]$pct) -CenterText ('{0:N1}%' -f [double]$pct) -ToneVar $tone -AriaLabel ('{0:N1} percent of memory in use' -f [double]$pct)
                $row += ('<div class="stat" style="display:flex;gap:14px;align-items:center;grid-column:1/-1">{0}<div><div class="slabel">Memory in use</div><div class="svalue">{1:N1}%</div><div class="ssub">{2} free of {3}</div></div></div>' -f $ring, [double]$pct, (ConvertTo-HtmlValue $freeText), (ConvertTo-HtmlValue $totalText))
            }
            foreach ($st in @($w['sticks'] | Where-Object { $_ })) {
                $bits = @()
                if ($st.speed) { $bits += [string]$st.speed }
                if ($st.type) { $bits += [string]$st.type }
                $sub = ($bits -join ' / ')
                if ($st.part) { if ($sub -ne '') { $sub += ' / ' }; $sub += [string]$st.part }
                $row += (ConvertTo-HtmlMiniCard -Icon 'memory' -Name ([string]$st.size) -Sub $sub -Right '')
            }
            if ($row -ne '') { $out = ('<div class="wrow">{0}</div>' -f $row) }
        }
        'Graphics' {
            $row = ''
            foreach ($ad in @($w['adapters'])) {
                if (-not $ad.name) { continue }
                $bits = @()
                if ($ad.vram) { $bits += [string]$ad.vram }
                if ($ad.mode) { $bits += [string]$ad.mode }
                if ($ad.driver) { $bits += ('driver ' + [string]$ad.driver) }
                $row += (ConvertTo-HtmlMiniCard -Icon 'gpu' -Name ([string]$ad.name) -Sub ($bits -join ' / ') -Right '')
            }
            if ($row -ne '') { $out = ('<div class="wrow">{0}</div>' -f $row) }
        }
        'Displays' {
            $row = ''
            foreach ($mon in @($w['monitors'] | Where-Object { $_ })) {
                $bits = @()
                if ($mon.mfr) { $bits += [string]$mon.mfr }
                if ($mon.size) { $bits += [string]$mon.size }
                if ($mon.bright) { $bits += [string]$mon.bright }
                $row += (ConvertTo-HtmlMiniCard -Icon 'display' -Name ([string]$mon.name) -Sub ($bits -join ' / ') -Right '')
            }
            if ($row -ne '') { $out = ('<div class="wrow">{0}</div>' -f $row) }
        }
        'Storage' {
            $row = ''
            foreach ($d in @($w['disks'] | Where-Object { $_ })) {
                $tone = Get-ToneFromText ([string]$d.health)
                $pillIcon = 'unknown'
                if ($tone -eq 'ok') { $pillIcon = 'ok' }
                elseif ($tone -eq 'warn') { $pillIcon = 'warn' }
                elseif ($tone -eq 'bad') { $pillIcon = 'bad' }
                $pill = ''
                if ($d.health) { $pill = (ConvertTo-HtmlPill -Tone $tone -Icon $pillIcon -Text ([string]$d.health) -Title 'Drive health (SMART)') }
                $subBits = @()
                if ($d.size) { $subBits += [string]$d.size }
                if ($d.type) { $subBits += [string]$d.type }
                if ($d.bus) { $subBits += [string]$d.bus }
                $meta = ''
                $cellParts = @()
                $cellParts += ('<div><div class="dmk">Temperature</div><div class="dmv">{0}</div></div>' -f (ConvertTo-HtmlValue $d.temp))
                $cellParts += ('<div><div class="dmk">Power-on</div><div class="dmv">{0}</div></div>' -f (ConvertTo-HtmlValue $d.hours))
                $cellParts += ('<div><div class="dmk">Wear</div><div class="dmv">{0}</div></div>' -f (ConvertTo-HtmlValue $d.wear))
                $meta = ('<div class="dmeta">{0}</div>' -f ($cellParts -join ''))
                $bar = ''
                if ($null -ne $d.wearNum) {
                    $wtone = 'ok'
                    if ([int]$d.wearNum -ge 60) { $wtone = 'warn' }
                    if ([int]$d.wearNum -ge 85) { $wtone = 'bad' }
                    $bar = ('<div class="barline">{0}<div class="barlegend"><span>Wear {1}% of rated life</span><span></span></div></div>' -f (ConvertTo-HtmlBar -Pct ([double]$d.wearNum) -ToneVar (Get-ToneVar $wtone) -AriaLabel ('{0} percent wear' -f $d.wearNum)), (ConvertTo-HtmlText ([string]$d.wearNum)))
                }
                $row += ('<div class="dcard"><div class="dchead"><span class="dcicon">{0}</span><div style="min-width:0"><div class="dcname">{1}</div><div class="dcsize">{2}</div></div>{3}</div>{4}{5}</div>' -f (Get-SsIcon 'disk'), (ConvertTo-HtmlText ([string]$d.name)), (ConvertTo-HtmlText ($subBits -join ' / ')), $pill, $meta, $bar)
            }
            foreach ($v in @($w['volumes'])) {
                if ($null -eq $v.freePct) { continue }
                $vtone = 'ok'
                if ([double]$v.freePct -le 10) { $vtone = 'bad' }
                elseif ([double]$v.freePct -le 25) { $vtone = 'warn' }
                $nameText = [string]$v.letter
                if ($v.label) { $nameText = '{0}  {1}' -f $v.letter, $v.label }
                $subBits = @()
                if ($v.fs) { $subBits += [string]$v.fs }
                if ($v.type) { $subBits += [string]$v.type }
                $freeText = Format-ByteSize $v.free
                $sizeText = Format-ByteSize $v.size
                $barHtml = ConvertTo-HtmlBar -Pct ([double]$v.freePct) -ToneVar (Get-ToneVar $vtone) -AriaLabel ('{0:N1} percent free' -f [double]$v.freePct)
                $row += ('<div class="vcard"><div class="dchead"><span class="dcicon">{0}</span><div style="min-width:0"><div class="dcname">{1}</div><div class="dcsize">{2}</div></div></div><div class="barline">{3}<div class="barlegend"><span>{4} free of {5}</span><span>{6:N1}%</span></div></div></div>' -f (Get-SsIcon 'disk'), (ConvertTo-HtmlText $nameText), (ConvertTo-HtmlText ($subBits -join ' / ')), $barHtml, (ConvertTo-HtmlValue $freeText), (ConvertTo-HtmlValue $sizeText), [double]$v.freePct)
            }
            if ($row -ne '') { $out = ('<div class="wrow">{0}</div>' -f $row) }
        }
        'Network' {
            $row = ''
            foreach ($cn in @($w['connections'] | Where-Object { $_ })) {
                $ledCls = 'led'
                $stateText = [string]$cn.status
                if ($cn.connected) { $ledCls = 'led ok' }
                $subBits = @()
                if ($cn.type) { $subBits += [string]$cn.type }
                if ($stateText) { $subBits += $stateText }
                if ($cn.connected -and $cn.speed) { $subBits += [string]$cn.speed }
                $rows = ''
                foreach ($pair in @(@('IPv4', $cn.ipv4), @('MAC', $cn.mac), @('Gateway', $cn.gateway), @('DNS', $cn.dns))) {
                    $pv = $pair[1]
                    if (-not $pv) { continue }
                    $rows += ('<div class="crow"><span class="ck">{0}</span><span class="cv mono copyable" data-copy="{1}">{2}</span></div>' -f (ConvertTo-HtmlText ([string]$pair[0])), (ConvertTo-HtmlText ([string]$pv)), (ConvertTo-HtmlText ([string]$pv)))
                }
                $metaHtml = ''
                if ($rows -ne '') { $metaHtml = ('<div class="cmeta">{0}</div>' -f $rows) }
                $row += ('<div class="ccard"><div class="ledrow"><span class="{0}"></span><div style="min-width:0"><div class="dcname">{1}</div><div class="dcsize">{2}</div></div></div>{3}</div>' -f $ledCls, (ConvertTo-HtmlText ([string]$cn.conn)), (ConvertTo-HtmlText ($subBits -join ' / ')), $metaHtml)
            }
            if ($row -ne '') { $out = ('<div class="wrow">{0}</div>' -f $row) }
        }
        'Battery' {
            $row = ''
            $charge = $w['charge']
            if ($null -ne $charge) {
                $ctone = 'ok'
                if ([int]$charge -le 20) { $ctone = 'warn' }
                if ([int]$charge -le 10) { $ctone = 'bad' }
                $ring = ConvertTo-HtmlRing -Pct ([double]$charge) -CenterText ('{0}%' -f $charge) -ToneVar (Get-ToneVar $ctone) -AriaLabel ('{0} percent charge' -f $charge)
                $statusText = [string]$w['status']
                $sub = 'charge remaining'
                if ($statusText) { $sub = $statusText }
                $row += ('<div class="stat" style="display:flex;gap:14px;align-items:center">{0}<div><div class="slabel">Charge</div><div class="svalue">{1}%</div><div class="ssub">{2}</div></div></div>' -f $ring, (ConvertTo-HtmlText ([string]$charge)), (ConvertTo-HtmlText $sub))
            }
            $health = $w['health']
            if ($null -ne $health) {
                $htone = 'ok'
                if ([double]$health -lt 80) { $htone = 'warn' }
                if ([double]$health -lt 60) { $htone = 'bad' }
                $barHtml = ConvertTo-HtmlBar -Pct ([double]$health) -ToneVar (Get-ToneVar $htone) -AriaLabel ('{0:N1} percent battery health' -f [double]$health)
                $cyclesText = ''
                if ($null -ne $w['cycles']) { $cyclesText = ('{0} charge cycles' -f $w['cycles']) }
                $row += ('<div class="stat"><div class="slabel">Battery health</div><div class="svalue">{0:N1}%</div><div class="barline">{1}<div class="barlegend"><span>of design capacity</span><span>{2}</span></div></div></div>' -f [double]$health, $barHtml, (ConvertTo-HtmlText $cyclesText))
            }
            if ($row -ne '') { $out = ('<div class="wrow">{0}</div>' -f $row) }
        }
        'Security' {
            $cards = ''
            foreach ($ck in @($w['checks'] | Where-Object { $_ })) {
                $st = [string]$ck.status
                $icon = 'info'
                $pillTone = 'info'
                $pillText = 'Info'
                if ($st -eq 'ok') { $icon = 'ok'; $pillTone = 'ok'; $pillText = 'Pass' }
                elseif ($st -eq 'warn') { $icon = 'warn'; $pillTone = 'warn'; $pillText = 'Review' }
                elseif ($st -eq 'bad') { $icon = 'bad'; $pillTone = 'bad'; $pillText = 'Action' }
                $detailHtml = ''
                if ($ck.detail) { $detailHtml = ('<div class="cdesc">Status: {0}</div>' -f (ConvertTo-HtmlText ([string]$ck.detail))) }
                $cards += ('<div class="check"><span class="cicon t-{0}">{1}</span><div class="cbody"><div class="cname">{2}<span class="pill t-{3}">{4}</span></div>{5}<div class="cdesc">{6}</div></div></div>' -f $pillTone, (Get-SsIcon $icon), (ConvertTo-HtmlText ([string]$ck.label)), $pillTone, $pillText, $detailHtml, (ConvertTo-HtmlText ([string]$ck.desc)))
            }
            if ($cards -ne '') { $out = ('<div class="checks">{0}</div>' -f $cards) }
        }
        'Windows' {
            $tiles = ''
            $act = [string]$w['activation']
            if ($act) {
                $tiles += (ConvertTo-HtmlStat -Label 'Activation' -Value $act -Icon 'windows')
            }
            if ($w['build']) { $tiles += (ConvertTo-HtmlStat -Label 'Build' -Value ([string]$w['build']) -Icon 'board') }
            if ($null -ne $w['updateCount']) { $tiles += (ConvertTo-HtmlStat -Label 'Installed updates' -Value ([string]$w['updateCount']) -Icon 'package') }
            if ($w['lastUpdate']) { $tiles += (ConvertTo-HtmlStat -Label 'Last update' -Value ([string]$w['lastUpdate']) -Icon 'calendar' -Sub ([string]$w['lastUpdateId'])) }
            if ($tiles -ne '') { $out = ('<div class="wrow">{0}</div>' -f $tiles) }
            $updates = @($w['updates'] | Where-Object { $_ })
            if ($updates.Count -gt 0) {
                $tl = ''
                foreach ($u in $updates) {
                    $tl += ('<div class="tli"><div class="tlhead"><span class="tlname mono">{0}</span><span class="tldate">{1}</span></div><div class="tldesc">{2}</div></div>' -f (ConvertTo-HtmlText ([string]$u.id)), (ConvertTo-HtmlText ([string]$u.date)), (ConvertTo-HtmlText ([string]$u.desc)))
                }
                $out += ('<div class="tl">{0}</div>' -f $tl)
            }
        }
        'Peripherals' {
            $pills = ''
            foreach ($cl in @($w['classes'] | Where-Object { $_ })) {
                $pills += ('<span class="pill t-accent">{0}<b>{1}</b></span>' -f (ConvertTo-HtmlText ([string]$cl.name)), [int]$cl.count)
            }
            if ($pills -ne '') { $out = ('<div style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 2px">{0}</div>' -f $pills) }
        }
        'Software' {
            if ($null -ne $w['count']) {
                $out = ('<div class="wrow">{0}</div>' -f (ConvertTo-HtmlStat -Label 'Applications detected' -Value ([string]$w['count']) -Icon 'package' -Sub 'From the uninstall registry, MSI products and Store packages'))
            }
        }
        'Services' {
            if ($null -ne $w['count']) {
                $out = ('<div class="wrow">{0}</div>' -f (ConvertTo-HtmlStat -Label 'Services running' -Value ([string]$w['count']) -Icon 'services'))
            }
        }
    }
    return $out
}

function ConvertTo-HtmlSection {
    param([string]$Key, $Section)
    $iconName = 'info'
    $accent = 'lavender'
    if ($Script:SectionMeta.Contains($Key)) {
        $iconName = $Script:SectionMeta[$Key].icon
        $accent = $Script:SectionMeta[$Key].accent
    }
    $body = ConvertTo-HtmlWidget -Key $Key -Section $Section
    foreach ($n in $Section.notes) {
        $body += ('<div class="note"><span class="ni">{0}</span><span>{1}</span></div>' -f (Get-SsIcon 'info'), (ConvertTo-HtmlText ([string]$n)))
    }
    $body += (ConvertTo-HtmlPairTable $Section.pairs)
    foreach ($t in $Section.tables) { $body += (ConvertTo-HtmlDataTable $t) }

    $itemCount = $Section.pairs.Keys.Count
    foreach ($t in $Section.tables) { $itemCount += @($t.rows).Count }
    $countChip = ''
    if ($itemCount -gt 0) {
        $entryWord = 'entries'
        if ($itemCount -eq 1) { $entryWord = 'entry' }
        $countChip = ('<span class="chip">{0} {1}</span>' -f $itemCount, $entryWord)
    }

    $sub = ''
    if ($Section.subtitle) { $sub = ('<span class="secsub">{0}</span>' -f (ConvertTo-HtmlText ([string]$Section.subtitle))) }

    $html = ('<details class="card" id="sec-{0}" open style="--accent:var(--fg-{1})">' -f $Key.ToLowerInvariant(), $accent)
    $html += ('<summary><span class="secc">{0}</span><span class="sect"><h2>{1}</h2>{2}</span><span class="right">{3}<span class="chev">{4}</span></span></summary>' -f (Get-SsIcon $iconName), (ConvertTo-HtmlText $Section.title), $sub, $countChip, (Get-SsIcon 'chev'))
    $html += ('<div class="sec-body">{0}</div></details>' -f $body)
    return $html
}

function Get-DeviceType {
    param($Sys)
    if ($null -eq $Sys) { return 'PC' }
    $vm = [string]$Sys.widgets['vm']
    if ($vm -match '(?i)^yes') { return 'virtual machine' }
    $ch = ([string]$Sys.widgets['chassis']).ToLowerInvariant()
    if ($ch -match 'laptop|notebook|portable|sub|convertible') { return 'laptop' }
    if ($ch -match 'desktop|tower|mini|all-in-one|space|pizza|lunch|low profile|main system') { return 'desktop PC' }
    if ($ch -ne '') { return ('PC - {0}' -f $Sys.widgets['chassis']) }
    return 'PC'
}

function ConvertTo-SummaryText {
    # One plain-language paragraph any reader can understand.
    param($Data)
    $out = New-Object System.Collections.ArrayList
    $s1 = 'This is a {0}' -f (Get-DeviceType $Data['System'])
    $os = $null
    if ($Data.Contains('Windows')) { $os = ([string]$Data['Windows'].summary['OS']).Trim() }
    if ($os) { $s1 += (' running {0}' -f $os) }
    $memText = $null
    if ($Data.Contains('Memory')) {
        $mw0 = $Data['Memory'].widgets
        $memSource = $null
        if ($mw0['installedBytes']) { $memSource = $mw0['installedBytes'] }
        elseif ($mw0['totalBytes']) { $memSource = $mw0['totalBytes'] }
        if ($memSource) { $memText = Format-ByteSize $memSource }
    }
    if ($memText) { $s1 += (' with {0} of RAM' -f $memText) }
    $cpuName = $null
    if ($Data.Contains('CPU')) { $cpuName = ([string]$Data['CPU'].summary['CPU']).Trim() }
    if ($cpuName) { $s1 += (', powered by {0}' -f $cpuName) }
    $gpuName = $null
    if ($Data.Contains('Graphics')) { $gpuName = ([string]$Data['Graphics'].summary['GPU']).Trim() }
    if ($gpuName) { $s1 += (', with {0} for graphics' -f $gpuName) }
    [void]$out.Add($s1 + '.')
    if ($Data.Contains('Storage')) {
        $sw = $Data['Storage'].widgets
        $disks = @($sw['disks'] | Where-Object { $_ })
        if ($disks.Count -gt 0 -and $sw['totalBytes']) {
            $diskWord = 'disks'
            if ($disks.Count -eq 1) { $diskWord = 'disk' }
            [void]$out.Add(('Storage: {0} physical {1}, {2} total with {3} free.' -f $disks.Count, $diskWord, (Format-ByteSize $sw['totalBytes']), (Format-ByteSize $sw['freeBytes'])))
            $healthy = @($disks | Where-Object { ([string]$_.health) -match '(?i)healthy|^ok' }).Count
            if ($healthy -eq $disks.Count) { [void]$out.Add('All disks report healthy.') }
            elseif ($healthy -gt 0) { [void]$out.Add(('{0} of {1} disks report healthy; see Storage for details.' -f $healthy, $disks.Count)) }
            else { [void]$out.Add('Disk health needs attention; see Storage for details.') }
        }
    }
    if ($Data.Contains('Security')) {
        $checks = @($Data['Security'].widgets['checks'] | Where-Object { $_ })
        if ($checks.Count -gt 0) {
            $okCount = @($checks | Where-Object { $_.status -eq 'ok' }).Count
            if ($okCount -eq $checks.Count) { [void]$out.Add(('All {0} security checks pass.' -f $checks.Count)) }
            else { [void]$out.Add(('{0} of {1} security checks pass; see Security for details.' -f $okCount, $checks.Count)) }
        }
    }
    if ($Data.Contains('Battery')) {
        $bw = $Data['Battery'].widgets
        if ($null -ne $bw['charge']) {
            $line = 'Battery at {0}%' -f $bw['charge']
            if ($null -ne $bw['health']) { $line += (', {0:N1}% health' -f [double]$bw['health']) }
            [void]$out.Add($line + '.')
        }
    }
    return ($out -join ' ')
}

function ConvertTo-HtmlHero {
    param($Data, $Meta)

    $devType = Get-DeviceType $Data['System']
    $summaryText = ConvertTo-SummaryText -Data $Data

    $rows = ''
    $os = $null
    if ($Data.Contains('Windows')) { $os = [string]$Data['Windows'].summary['OS'] }
    if ($os) { $rows += ('<div class="mrow"><span class="mk">OS</span><span class="mv">{0}</span></div>' -f (ConvertTo-HtmlText $os)) }
    $instVal = $null
    if ($Data.Contains('Windows')) { $instVal = [string]$Data['Windows'].summary['InstallDate'] }
    if ($instVal) { $rows += ('<div class="mrow"><span class="mk">Installed</span><span class="mv">{0}</span></div>' -f (ConvertTo-HtmlText $instVal)) }
    $boardVal = $null
    if ($Data.Contains('System')) { $boardVal = [string]$Data['System'].summary['Motherboard'] }
    if ($boardVal) { $rows += ('<div class="mrow"><span class="mk">Board</span><span class="mv">{0}</span></div>' -f (ConvertTo-HtmlText $boardVal)) }
    $biosVal = $null
    if ($Data.Contains('System')) { $biosVal = [string]$Data['System'].widgets['bios'] }
    if ($biosVal) { $rows += ('<div class="mrow"><span class="mk">Firmware</span><span class="mv">{0}</span></div>' -f (ConvertTo-HtmlText $biosVal)) }
    $uptimeVal = $null
    if ($Data.Contains('Windows')) { $uptimeVal = [string]$Data['Windows'].summary['Uptime'] }
    if ($uptimeVal) { $rows += ('<div class="mrow"><span class="mk">Uptime</span><span class="mv">{0}</span></div>' -f (ConvertTo-HtmlText $uptimeVal)) }
    $rows += ('<div class="mrow"><span class="mk">Scanned</span><span class="mv">{0} in {1} s</span></div>' -f (ConvertTo-HtmlText ([string]$Meta.Date)), (ConvertTo-HtmlText ([string]$Meta.Elapsed)))
    $ranAs = 'Standard user'
    if ($Meta.IsAdmin) { $ranAs = 'Administrator' }
    $rows += ('<div class="mrow"><span class="mk">Ran as</span><span class="mv">{0}</span></div>' -f (ConvertTo-HtmlText $ranAs))

    $hero = ('<section id="overview" class="hero" aria-label="Overview"><div class="tile tile-id" style="--accent:var(--fg-lavender)"><div class="idtop"><span class="devbadge">{0}{1}</span></div><h1>{2}</h1><p class="idsum">{3}</p><div class="idmeta">{4}</div></div>' -f (Get-SsIcon 'host'), (ConvertTo-HtmlText $devType), (ConvertTo-HtmlText ([string]$Meta.Hostname)), (ConvertTo-HtmlText $summaryText), $rows)

    # ---- KPI tiles ----
    $kpis = ''

    $cpuVal = $null
    $cpuSub = ''
    if ($Data.Contains('CPU')) {
        $cpuVal = ([string]$Data['CPU'].summary['CPU']).Trim()
        if ($Data['CPU'].subtitle) { $cpuSub = [string]$Data['CPU'].subtitle }
    }
    $kpis += ('<div class="tile kpi" style="--accent:var(--fg-mauve)"><div class="khead"><span class="kicon">{0}</span><span class="klabel">Processor</span></div><div class="kvalue">{1}</div><div class="ksub">{2}</div></div>' -f (Get-SsIcon 'cpu'), (ConvertTo-HtmlValue $cpuVal), (ConvertTo-HtmlValue $cpuSub))

    $memRing = ''
    $memVal = $null
    $memSub = ''
    if ($Data.Contains('Memory')) {
        $mw = $Data['Memory'].widgets
        if ($null -ne $mw['usedPct']) {
            $mtone = 'var(--fg-ok)'
            if ([double]$mw['usedPct'] -ge 90) { $mtone = 'var(--fg-bad)' }
            elseif ([double]$mw['usedPct'] -ge 75) { $mtone = 'var(--fg-warn)' }
            $memRing = ConvertTo-HtmlRing -Pct ([double]$mw['usedPct']) -CenterText ('{0:N0}%' -f [double]$mw['usedPct']) -ToneVar $mtone -AriaLabel ('{0} percent of memory in use' -f [double]$mw['usedPct'])
        }
        $memVal = Format-ByteSize $mw['totalBytes']
        if ($mw['installedBytes']) { $memVal = Format-ByteSize $mw['installedBytes'] }
        $bits = @()
        if ($mw['freeBytes']) { $bits += ((Format-ByteSize $mw['freeBytes']) + ' free') }
        $stickCount = @($mw['sticks'] | Where-Object { $_ }).Count
        if ($stickCount -gt 0) {
            $moduleWord = 'modules'
            if ($stickCount -eq 1) { $moduleWord = 'module' }
            $bits += ('{0} {1}' -f $stickCount, $moduleWord)
        }
        if ($mw['slots']) { $bits += ('{0} slots' -f $mw['slots']) }
        $memSub = ($bits -join ' / ')
    }
    $memBody = ''
    if ($memRing -ne '') { $memBody = ('<div class="krow">{0}<div><div class="kvalue">{1}</div><div class="ksub">{2}</div></div></div>' -f $memRing, (ConvertTo-HtmlValue $memVal), (ConvertTo-HtmlValue $memSub)) }
    else { $memBody = ('<div class="kvalue">{0}</div><div class="ksub">{1}</div>' -f (ConvertTo-HtmlValue $memVal), (ConvertTo-HtmlValue $memSub)) }
    $kpis += ('<div class="tile kpi" style="--accent:var(--fg-blue)"><div class="khead"><span class="kicon">{0}</span><span class="klabel">Memory</span></div>{1}</div>' -f (Get-SsIcon 'memory'), $memBody)

    $gpuVal = $null
    $gpuSub = ''
    if ($Data.Contains('Graphics')) {
        $gpuVal = ([string]$Data['Graphics'].summary['GPU']).Trim()
        $adapters = @($Data['Graphics'].widgets['adapters'] | Where-Object { $_ })
        if ($adapters.Count -gt 0) {
            $bits = @()
            if ($adapters[0].vram) { $bits += [string]$adapters[0].vram }
            if ($adapters[0].driver) { $bits += ('driver ' + [string]$adapters[0].driver) }
            $gpuSub = ($bits -join ' / ')
        }
    }
    $kpis += ('<div class="tile kpi" style="--accent:var(--fg-sapphire)"><div class="khead"><span class="kicon">{0}</span><span class="klabel">Graphics</span></div><div class="kvalue">{1}</div><div class="ksub">{2}</div></div>' -f (Get-SsIcon 'gpu'), (ConvertTo-HtmlValue $gpuVal), (ConvertTo-HtmlValue $gpuSub))

    $stVal = $null
    $stSub = ''
    $stBar = ''
    if ($Data.Contains('Storage')) {
        $sw = $Data['Storage'].widgets
        $stVal = Format-ByteSize $sw['totalBytes']
        $disks = @($sw['disks'] | Where-Object { $_ })
        $bits = @()
        if ($disks.Count -gt 0) {
            $diskWord = 'disks'
            if ($disks.Count -eq 1) { $diskWord = 'disk' }
            $bits += ('{0} {1}' -f $disks.Count, $diskWord)
        }
        if ($sw['freeBytes']) { $bits += ((Format-ByteSize $sw['freeBytes']) + ' free') }
        $stSub = ($bits -join ' / ')
        if ($sw['totalBytes'] -and [double]$sw['totalBytes'] -gt 0) {
            $usedPct = [Math]::Round(((($sw['totalBytes'] - $sw['freeBytes']) / $sw['totalBytes']) * 100), 1)
            $freePct = 100 - $usedPct
            $stTone = 'ok'
            if ($freePct -le 10) { $stTone = 'bad' }
            elseif ($freePct -le 25) { $stTone = 'warn' }
            $stBar = ('<div class="barline">{0}<div class="barlegend"><span>{1:N1}% used</span><span>{2}</span></div></div>' -f (ConvertTo-HtmlBar -Pct $usedPct -ToneVar (Get-ToneVar $stTone) -AriaLabel ('{0:N1} percent used' -f $usedPct)), $usedPct, (ConvertTo-HtmlValue $stSub))
        }
    }
    $stBody = ''
    if ($stBar -ne '') { $stBody = ('<div class="kvalue">{0}</div>{1}' -f (ConvertTo-HtmlValue $stVal), $stBar) }
    else { $stBody = ('<div class="kvalue">{0}</div><div class="ksub">{1}</div>' -f (ConvertTo-HtmlValue $stVal), (ConvertTo-HtmlValue $stSub)) }
    $kpis += ('<div class="tile kpi" style="--accent:var(--fg-teal)"><div class="khead"><span class="kicon">{0}</span><span class="klabel">Storage</span></div>{1}</div>' -f (Get-SsIcon 'disk'), $stBody)

    # ---- Health strip ----
    $pills = ''
    if ($Data.Contains('Storage')) {
        $disks2 = @($Data['Storage'].widgets['disks'] | Where-Object { $_ })
        if ($disks2.Count -gt 0) {
            $healthy2 = @($disks2 | Where-Object { ([string]$_.health) -match '(?i)healthy|^ok' }).Count
            $tone = 'ok'
            if ($healthy2 -lt $disks2.Count) { $tone = 'warn' }
            $pills += (ConvertTo-HtmlPill -Tone $tone -Icon 'disk' -Text ('Disks {0}/{1} healthy' -f $healthy2, $disks2.Count) -Title 'Physical disk health as reported by SMART')
        }
    }
    if ($Data.Contains('Security')) {
        foreach ($ck in @($Data['Security'].widgets['checks'] | Where-Object { $_ })) {
            $tone = 'info'
            if ($ck.status -eq 'ok') { $tone = 'ok' }
            elseif ($ck.status -eq 'warn') { $tone = 'warn' }
            elseif ($ck.status -eq 'bad') { $tone = 'bad' }
            $ttl = ('{0} Current status: {1}' -f [string]$ck.desc, [string]$ck.detail)
            $pills += (ConvertTo-HtmlPill -Tone $tone -Icon 'shield' -Text ([string]$ck.label) -Title $ttl)
        }
    }
    if ($Data.Contains('Battery') -and $null -ne $Data['Battery'].widgets['health']) {
        $h = [double]$Data['Battery'].widgets['health']
        $tone = 'ok'
        if ($h -lt 80) { $tone = 'warn' }
        if ($h -lt 60) { $tone = 'bad' }
        $pills += (ConvertTo-HtmlPill -Tone $tone -Icon 'battery' -Text ('Battery {0:N0}%' -f $h) -Title 'Estimated battery health vs design capacity')
    }
    $health = ''
    if ($pills -ne '') { $health = ('<div class="health"><span class="hh">System health</span>{0}</div>' -f $pills) }

    return ($hero + ('<div class="kpis">{0}</div>' -f $kpis) + $health + '</section>')
}

function ConvertTo-HtmlReport {
    param($Data, $Meta, $Order)

    $nav = ''
    $sections = ''
    $i = 0
    foreach ($key in $Order) {
        if (-not $Data.Contains($key)) { continue }
        $sec = $Data[$key]
        $sections += (ConvertTo-HtmlSection -Key $key -Section $sec)
        $nav += ('<a href="#sec-{0}">{1}</a>' -f $key.ToLowerInvariant(), (ConvertTo-HtmlText $sec.title))
        $i++
    }

    $hero = ConvertTo-HtmlHero -Data $Data -Meta $Meta

    $banner = ''
    if (-not $Meta.IsAdmin -or $Script:Warnings.Count -gt 0) {
        $items = ''
        if (-not $Meta.IsAdmin) {
            $items += '<li>Some details (SMART wear data, BitLocker, some battery fields) need an elevated run. Re-run SpecsScanner from an administrator PowerShell for full coverage.</li>'
        }
        foreach ($wn in $Script:Warnings) {
            $items += ('<li>{0}</li>' -f (ConvertTo-HtmlText ([string]$wn)))
        }
        $cls = 'banner'
        $icon = 'info'
        $headText = 'Collection notes'
        if (-not $Meta.IsAdmin) { $headText = 'Standard-user scan' }
        if ($Script:Warnings.Count -gt 0) { $cls = 'banner warn'; $icon = 'warn' }
        $banner = ('<div class="{0}"><span class="bi">{1}</span><div><strong>{2}</strong><ul>{3}</ul></div></div>' -f $cls, (Get-SsIcon $icon), (ConvertTo-HtmlText $headText), $items)
    }

    $adminPill = 't-warn'
    $adminTag = 'Standard user scan'
    $adminIcon = 'warn'
    if ($Meta.IsAdmin) { $adminPill = 't-info'; $adminTag = 'Administrator scan'; $adminIcon = 'ok' }
    $adminTagHtml = (Get-SsIcon $adminIcon) + $adminTag

    $isRedacted = $false
    if ($Meta.Contains('Redacted')) { $isRedacted = [bool]$Meta['Redacted'] }
    $redactChip = ''
    if ($isRedacted) {
        $redactChip = ('<span class="pill t-accent" title="Sharing-safe copy: hostname, user names, serials, MACs and IP addresses were replaced with placeholders">{0}Redacted copy</span>' -f (Get-SsIcon 'shield'))
    }

    $themeName = 'mocha'
    if ($Meta.Theme) { $themeName = ([string]$Meta.Theme).ToLowerInvariant() }
    if (@('mocha', 'latte', 'auto') -notcontains $themeName) { $themeName = 'mocha' }
    $defTheme = $themeName
    $initialTheme = $themeName
    if ($initialTheme -eq 'auto') { $initialTheme = 'mocha' }

    $accentName = 'mauve'
    if ($Meta.Contains('Accent') -and $Meta['Accent']) { $accentName = ([string]$Meta['Accent']).ToLowerInvariant() }

    $redactNote = ''
    if ($isRedacted) { $redactNote = ' &middot; identifiers redacted for safe sharing' }

    $head = $Script:TemplateHead
    $head = $head.Replace('{{THEME}}', $initialTheme)
    $head = $head.Replace('{{DEFTHEME}}', $defTheme)
    $head = $head.Replace('{{BRAND}}', $accentName)
    $head = $head.Replace('{{TITLE}}', (ConvertTo-HtmlText ('SpecsScanner - {0}' -f $Meta.Hostname)))
    $head = $head.Replace('{{VERSION}}', $Script:Version)
    $head = $head.Replace('{{HOST}}', (ConvertTo-HtmlText ([string]$Meta.Hostname)))
    $head = $head.Replace('{{ADMINTAG}}', $adminTagHtml)
    $head = $head.Replace('{{ADMINPILL}}', $adminPill)
    $head = $head.Replace('{{REDACTCHIP}}', $redactChip)
    $head = $head.Replace('{{ICON_HOST}}', (Get-SsIcon 'host'))
    $head = $head.Replace('{{ICON_SEARCH}}', (Get-SsIcon 'search'))
    $head = $head.Replace('{{ICON_AUTO}}', (Get-SsIcon 'auto'))
    $head = $head.Replace('{{ICON_SUN}}', (Get-SsIcon 'sun'))
    $head = $head.Replace('{{ICON_MOON}}', (Get-SsIcon 'moon'))
    $head = $head.Replace('{{ICON_FOLD}}', (Get-SsIcon 'fold'))
    $head = $head.Replace('{{ICON_PRINT}}', (Get-SsIcon 'print'))
    $head = $head.Replace('{{NAV}}', '<a href="#overview">Overview</a>' + $nav)
    $head = $head.Replace('{{HERO}}', $hero)
    $head = $head.Replace('{{BANNER}}', $banner)

    $foot = $Script:TemplateFoot
    $foot = $foot.Replace('{{VERSION}}', $Script:Version)
    $foot = $foot.Replace('{{DATE}}', (ConvertTo-HtmlText ([string]$Meta.Date)))
    $foot = $foot.Replace('{{ELAPSED}}', (ConvertTo-HtmlText ([string]$Meta.Elapsed)))
    $foot = $foot.Replace('{{SECTIONS}}', [string]$i)
    $foot = $foot.Replace('{{PSV}}', (ConvertTo-HtmlText ([string]$Meta.PSVersion)))
    $foot = $foot.Replace('{{REDACTNOTE}}', $redactNote)
    $foot = $foot.Replace('{{ICON_UP}}', (Get-SsIcon 'up'))

    return $head + $sections + $foot
}

# ---------------------------------------------------------------------------
# Redaction (-Redact): replace identifiers with share-safe placeholders
# ---------------------------------------------------------------------------
function ConvertTo-RedactedValue {
    param($Value, [string]$KeyName, $State)
    if ($null -eq $Value) { return $Value }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [array]) { return $Value }
    $isScalar = $Value -is [string] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]
    if (-not $isScalar) { return $Value }
    $s = [string]$Value
    if ([string]::IsNullOrEmpty($s)) { return $Value }
    if ($KeyName) {
        if ($KeyName -match '(?i)serial|asset tag|service tag') {
            if (-not $State.SerialMap.ContainsKey($s)) {
                $State.SerialN = [int]$State.SerialN + 1
                $State.SerialMap[$s] = ('EX-SERIAL-{0:D3}' -f $State.SerialN)
            }
            return $State.SerialMap[$s]
        }
        if ($KeyName -match '(?i)ssid') { return 'EXAMPLE-NETWORK' }
        if ($KeyName -match '(?i)registered user|^user(name)?$|owner') { return 'EXAMPLE\user' }
        if ($KeyName -match '(?i)registered org') { return 'Example Corp' }
    }
    if ($State.UserFull -and ([string]$State.UserFull) -ne '' -and ([string]$State.UserFull) -ne ([string]$State.UserName)) {
        $s = [regex]::Replace($s, [regex]::Escape([string]$State.UserFull), 'EXAMPLE\user', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    if ($State.Host -and ([string]$State.Host) -ne '') {
        $s = [regex]::Replace($s, [regex]::Escape([string]$State.Host), 'DESKTOP-EXAMPLE', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    if ($State.UserName -and ([string]$State.UserName) -ne '') {
        $s = [regex]::Replace($s, [regex]::Escape([string]$State.UserName), 'user', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $macMatches = [regex]::Matches($s, '(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}')
    foreach ($mm in $macMatches) {
        $orig = $mm.Value
        if (-not $State.MacMap.ContainsKey($orig)) {
            $State.MacN = [int]$State.MacN + 1
            $n = [int]$State.MacN
            $State.MacMap[$orig] = ('02:00:00:00:{0:X2}:{1:X2}' -f [int][Math]::Floor($n / 256), ($n % 256))
        }
        $s = $s.Replace($orig, [string]$State.MacMap[$orig])
    }
    $ipMatches = [regex]::Matches($s, '(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])')
    foreach ($im in $ipMatches) {
        $o1 = [int]$im.Groups[1].Value
        $o2 = [int]$im.Groups[2].Value
        $o3 = [int]$im.Groups[3].Value
        $o4 = [int]$im.Groups[4].Value
        if ($o1 -gt 255 -or $o2 -gt 255 -or $o3 -gt 255 -or $o4 -gt 255) { continue }
        $orig = $im.Value
        if (-not $State.IpMap.ContainsKey($orig)) {
            $State.IpN = [int]$State.IpN + 1
            $State.IpMap[$orig] = ('192.0.2.{0}' -f ([int]$State.IpN % 256))
        }
        $s = $s.Replace($orig, [string]$State.IpMap[$orig])
    }
    $s = [regex]::Replace($s, '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '00000000-0000-0000-0000-000000000000')
    return $s
}

function Invoke-DataRedaction {
    # Walks every collected value and masks machine/user identifiers so the
    # report can be shared publicly. Called only when -Redact is set.
    param($Data, $Meta)
    $state = @{
        Host      = [string]$Meta['Hostname']
        UserFull  = [string]$Meta['User']
        UserName  = ''
        SerialN   = 0
        SerialMap = @{}
        MacN      = 0
        MacMap    = @{}
        IpN       = 0
        IpMap     = @{}
    }
    if ($state.UserFull -match '\\') { $state.UserName = ([string]$state.UserFull -split '\\')[-1] }
    foreach ($key in @($Data.Keys)) {
        $sec = $Data[$key]
        if ($sec.Contains('subtitle') -and $sec['subtitle']) {
            $sec['subtitle'] = ConvertTo-RedactedValue -Value $sec['subtitle'] -KeyName '' -State $state
        }
        foreach ($pk in @($sec.pairs.Keys)) {
            $sec.pairs[$pk] = ConvertTo-RedactedValue -Value $sec.pairs[$pk] -KeyName ([string]$pk) -State $state
        }
        foreach ($t in @($sec.tables)) {
            foreach ($row in @($t.rows)) {
                foreach ($ck in @($row.Keys)) {
                    $row[$ck] = ConvertTo-RedactedValue -Value $row[$ck] -KeyName ([string]$ck) -State $state
                }
            }
        }
        for ($i = 0; $i -lt $sec.notes.Count; $i++) {
            if ($sec.notes[$i] -is [string]) {
                $sec.notes[$i] = ConvertTo-RedactedValue -Value $sec.notes[$i] -KeyName '' -State $state
            }
        }
        if ($sec.widgets) {
            foreach ($wk in @($sec.widgets.Keys)) {
                $wv = $sec.widgets[$wk]
                if ($wv -is [string]) {
                    $sec.widgets[$wk] = ConvertTo-RedactedValue -Value $wv -KeyName ([string]$wk) -State $state
                } elseif ($null -ne $wv -and ($wv -is [System.Collections.IEnumerable]) -and ($wv -isnot [string])) {
                    foreach ($item in @($wv)) {
                        if ($item -is [System.Collections.IDictionary]) {
                            foreach ($ik in @($item.Keys)) {
                                $item[$ik] = ConvertTo-RedactedValue -Value $item[$ik] -KeyName ([string]$ik) -State $state
                            }
                        }
                    }
                }
            }
        }
        foreach ($sk in @($sec.summary.Keys)) {
            $sec.summary[$sk] = ConvertTo-RedactedValue -Value $sec.summary[$sk] -KeyName ([string]$sk) -State $state
        }
    }
    $Meta['Hostname'] = 'DESKTOP-EXAMPLE'
    $Meta['User'] = 'EXAMPLE\user'
    $Meta['Redacted'] = $true
}

# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
function ConvertTo-SpecsJson {
    param($Data, $Meta, $Order)
    $out = [ordered]@{}
    $out['scanner'] = [ordered]@{
        name       = 'SpecsScanner'
        version    = $Meta.Version
        generated  = $Meta.Date
        hostname   = $Meta.Hostname
        user       = $Meta.User
        elevated   = $Meta.IsAdmin
        powershell = $Meta.PSVersion
    }
    foreach ($key in $Order) {
        if (-not $Data.Contains($key)) { continue }
        $s = $Data[$key]
        $tablesJson = @()
        foreach ($t in $s.tables) {
            $colsJson = @()
            foreach ($c in $t.columns) { $colsJson += [ordered]@{ key = $c.key; label = $c.label } }
            $tablesJson += [ordered]@{ title = $t.title; columns = $colsJson; rows = @($t.rows) }
        }
        $out[$key] = [ordered]@{
            title  = $s.title
            values = [pscustomobject]$s.pairs
            tables = $tablesJson
            notes  = @($s.notes)
        }
    }
    return (ConvertTo-Json -InputObject $out -Depth 12)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host ''
Write-Host ('  SpecsScanner v{0}' -f $Script:Version) -ForegroundColor Magenta
if ($Script:IsAdmin) { Write-Host '  Running as Administrator - full detail mode' -ForegroundColor DarkGray }
else { Write-Host '  Running as standard user - a few security/storage details will be limited' -ForegroundColor DarkGray }
Write-Host ''

$enabledList = New-Object System.Collections.Generic.List[string]
if ($Sections -and @($Sections).Count -gt 0) {
    foreach ($entry in $Sections) {
        foreach ($part in ($entry -split ',')) {
            $p = $part.Trim()
            if (-not $p) { continue }
            $matchedAlias = $false
            foreach ($alias in $Script:SectionAliases.Keys) {
                if ($alias -ieq $p) {
                    foreach ($k in $Script:SectionAliases[$alias]) {
                        if (-not $enabledList.Contains($k)) { $enabledList.Add($k) }
                    }
                    $matchedAlias = $true
                    break
                }
            }
            if ($matchedAlias) { continue }
            $canon = $null
            foreach ($k in $Script:SectionTitles.Keys) {
                if ($k -ieq $p) { $canon = $k; break }
            }
            if ($canon) {
                if (-not $enabledList.Contains($canon)) { $enabledList.Add($canon) }
            } else {
                Write-Warning ('Unknown section "{0}" ignored.' -f $p)
            }
        }
    }
} else {
    foreach ($k in $Script:SectionTitles.Keys) { $enabledList.Add($k) }
}
$orderedKeys = @($Script:SectionTitles.Keys | Where-Object { $enabledList.Contains($_) })

$collectorMap = @{
    System      = { Read-System }
    CPU         = { Read-CPU }
    Memory      = { Read-Memory }
    Graphics    = { Read-GPU }
    Displays    = { Read-Display }
    Storage     = { Read-Storage }
    Network     = { Read-Network }
    Audio       = { Read-Audio }
    Battery     = { Read-Battery }
    Security    = { Read-Security }
    Windows     = { Read-Windows }
    Peripherals = { Read-Peripheral }
    Software    = { Read-Software }
    Services    = { Read-Service }
}

$data = [ordered]@{}
foreach ($key in $orderedKeys) {
    $label = $Script:SectionTitles[$key]
    try {
        $sec = & $collectorMap[$key]
        if ($sec -and -not $sec.skip) {
            $data[$key] = $sec
            Write-Host ('  [x] {0}' -f $label) -ForegroundColor DarkCyan
        } else {
            Write-Host ('  [-] {0} (not present on this system)' -f $label) -ForegroundColor DarkGray
        }
    } catch {
        [void]$Script:Warnings.Add(('{0}: {1}' -f $label, $_.Exception.Message))
        Write-Host ('  [!] {0} failed: {1}' -f $label, $_.Exception.Message) -ForegroundColor Yellow
    }
}
$sw.Stop()

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$meta = [ordered]@{
    Hostname  = $env:COMPUTERNAME
    User      = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    Date      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    IsAdmin   = $Script:IsAdmin
    Version   = $Script:Version
    PSVersion = $PSVersionTable.PSVersion.ToString()
    Theme     = $Theme
    Accent    = $Accent
    Redacted  = $false
    Elapsed   = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
}

if ($Redact) {
    Invoke-DataRedaction -Data $data -Meta $meta
    Write-Host '  Redaction: hostname, user names, serials, MACs and IPs replaced with placeholders' -ForegroundColor DarkYellow
}

$paths = Resolve-OutputPath -Path $OutputPath -Stamp $stamp
$written = New-Object System.Collections.ArrayList

if ($Format -eq 'Html' -or $Format -eq 'Both') {
    $html = ConvertTo-HtmlReport -Data $data -Meta $meta -Order $orderedKeys
    Write-TextFile -Path $paths.html -Content $html
    [void]$written.Add($paths.html)
}
if ($Format -eq 'Json' -or $Format -eq 'Both') {
    $json = ConvertTo-SpecsJson -Data $data -Meta $meta -Order $orderedKeys
    Write-TextFile -Path $paths.json -Content $json
    [void]$written.Add($paths.json)
}

Write-Host ''
foreach ($f in $written) {
    $sizeText = ''
    if ([System.IO.File]::Exists($f)) {
        $sizeText = ' ({0})' -f (Format-ByteSize ([System.IO.FileInfo]$f).Length)
    }
    Write-Host ('  [OK] {0}{1}' -f $f, $sizeText) -ForegroundColor Green
}
Write-Host ('  Finished in {0:N1}s' -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray

if ($Script:Warnings.Count -gt 0) {
    Write-Host ''
    Write-Host '  Collection notes:' -ForegroundColor Yellow
    foreach ($w in $Script:Warnings) { Write-Host ('   - {0}' -f $w) -ForegroundColor DarkYellow }
}

if (-not $NoOpen -and $Format -ne 'Json') {
    Invoke-Safe { Start-Process -FilePath $paths.html } | Out-Null
}
Write-Host ''
