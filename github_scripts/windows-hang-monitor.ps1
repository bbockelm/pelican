# DIAGNOSTIC ONLY (branch windows-hang-diag).
#
# Runs beside "go test" on a Windows runner.  It reports the machine's state
# into the step's log, and if the machine looks about to run out of memory,
# commit, disk or handles -- which has been taking the whole runner down, so
# that no log survives -- it dumps every process with its command line and
# kills the Go test binaries, so the step ends and its log is kept.

param([string]$Sentinel)

$checkSeconds = 5
$reportEvery = 4          # report every 4th check (20s)
$minFreeMiB = 1500        # physical memory
$minCommitMiB = 1500      # commit (virtual) memory
$minDiskGiB = 3           # each fixed drive
$maxHandles = 50000       # any one process
$maxThreads = 3000        # any one process

function Write-Top($label) {
    Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 6 | ForEach-Object {
        "MACHINE   {0} {1} pid={2} ws={3:N0}M private={4:N0}M cpu={5:N0}s handles={6} threads={7}" -f $label, $_.ProcessName, $_.Id, ($_.WorkingSet64/1MB), ($_.PrivateMemorySize64/1MB), $_.CPU, $_.HandleCount, $_.Threads.Count
    }
}

$n = 0
while ($true) {
    # The step removes the sentinel when it ends; exit so the step can finish.
    if ($Sentinel -and -not (Test-Path -LiteralPath $Sentinel)) { exit 0 }
    $n++
    $os = Get-CimInstance Win32_OperatingSystem
    $memFree = $os.FreePhysicalMemory / 1KB
    $commitFree = $os.FreeVirtualMemory / 1KB
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
    $disks = ($drives | ForEach-Object { "{0}:free={1:N1}G" -f $_.Name, ($_.Free/1GB) }) -join " "
    $procs = Get-Process
    $line = "MACHINE {0:HH:mm:ss} memfree={1:N0}M commitfree={2:N0}M procs={3} {4}" -f (Get-Date), $memFree, $commitFree, $procs.Count, $disks

    $reason = $null
    if ($memFree -lt $minFreeMiB) { $reason = "memfree {0:N0}M" -f $memFree }
    elseif ($commitFree -lt $minCommitMiB) { $reason = "commitfree {0:N0}M" -f $commitFree }
    else {
        $low = $drives | Where-Object { $_.Free / 1GB -lt $minDiskGiB } | Select-Object -First 1
        if ($low) { $reason = "drive {0}: free {1:N1}G" -f $low.Name, ($low.Free/1GB) }
        else {
            $big = $procs | Where-Object { $_.HandleCount -gt $maxHandles -or $_.Threads.Count -gt $maxThreads } | Select-Object -First 1
            if ($big) { $reason = "{0} pid={1} handles={2} threads={3}" -f $big.ProcessName, $big.Id, $big.HandleCount, $big.Threads.Count }
        }
    }

    if ($reason) {
        "MACHINE TRIPPED: $reason"
        $line
        Get-CimInstance Win32_Process | Sort-Object WorkingSetSize -Descending | ForEach-Object {
            "MACHINE DUMP pid={0} ppid={1} ws={2:N0}M handles={3} threads={4} {5}" -f $_.ProcessId, $_.ParentProcessId, ($_.WorkingSetSize/1MB), $_.HandleCount, $_.ThreadCount, $_.CommandLine
        }
        $tmp = [System.IO.Path]::GetTempPath()
        Get-ChildItem -Path $tmp -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $size = (Get-ChildItem -Path $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            [pscustomobject]@{ Name = $_.FullName; MiB = [math]::Round($size / 1MB) }
        } | Sort-Object MiB -Descending | Select-Object -First 15 | ForEach-Object { "MACHINE TEMP {0:N0}M {1}" -f $_.MiB, $_.Name }
        "MACHINE killing Go test binaries"
        Get-Process | Where-Object { $_.Path -like "*.test.exe" -or $_.ProcessName -like "*.test" } | ForEach-Object {
            "MACHINE kill {0} pid={1}" -f $_.ProcessName, $_.Id
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        # Keep watching: a second trip means the test binaries were not the cause.
        Start-Sleep -Seconds 30
        continue
    }

    if ($n % $reportEvery -eq 1) {
        $line
        Write-Top ""
    }
    Start-Sleep -Seconds $checkSeconds
}
