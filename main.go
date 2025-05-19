package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// --- Configuration ---
const (
	// !!! REPLACE WITH YOUR ACTUAL API ENDPOINT !!!
	apiEndpoint             = "http://localhost:3000/api/sysutil"
	checkIntervalMinutes    = 15
	stateFile               = "system_monitor_last_state.json"
	maxAllowedSleepMinutes  = 10
	logFile                 = "system_monitor.log"
	commandTimeoutSeconds   = 30 // Timeout for external commands
)

// --- Structs ---

// SystemState holds all collected information about the system.
type SystemState struct {
	Timestamp               string                  `json:"timestamp"`
	OS_Type                 string                  `json:"os_type"`
	Hostname                string                  `json:"hostname"`
	DiskEncryption          string                  `json:"disk_encryption"`
	OSUpdateStatus          string                  `json:"os_update_status"`
	AntivirusInfo           AntivirusInfo           `json:"antivirus_info"`
	InactivitySleepSettings InactivitySleepSettings `json:"inactivity_sleep_settings"`
}

// AntivirusInfo holds information about AV presence.
type AntivirusInfo struct {
	Presence string `json:"presence"`
	Details  string `json:"details"`
}

// InactivitySleepSettings holds sleep setting compliance.
type InactivitySleepSettings struct {
	ComplianceStatus   string `json:"compliance_status"`
	ConfiguredMinutes  int    `json:"configured_minutes"` // -1 if not found/error
}

var logger *log.Logger

// --- Helper Function to Run Commands ---
func runCommand(timeout time.Duration, name string, arg ...string) (stdout string, stderr string, exitCode int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, arg...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	stdout = strings.TrimSpace(outb.String())
	stderr = strings.TrimSpace(errb.String())

	if ctx.Err() == context.DeadlineExceeded {
		logger.Printf("Command timed out: %s %v", name, arg)
		return stdout, "Command timed out", -1 // Custom error code for timeout
	}

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			logger.Printf("Error running command '%s %v' (not ExitError): %v", name, arg, err)
			exitCode = -2 // Custom error code for other errors (e.g., command not found)
		}
		// Log stderr only if there was an error and stderr is not empty
		if stderr != "" {
			logger.Printf("Command error (stderr): %s", stderr)
		}
		return stdout, stderr, exitCode
	}

	return stdout, stderr, 0
}

// runCommandWithShell runs a command using the system's shell.
// Use with caution, especially if commandString incorporates external input.
func runCommandWithShell(timeout time.Duration, commandString string) (stdout string, stderr string, exitCode int) {
	var shell, flag string
	if runtime.GOOS == "windows" {
		shell = "powershell"
		flag = "-Command"
		// For complex PowerShell commands, might need to adjust execution policy or use -EncodedCommand
	} else {
		shell = "sh"
		flag = "-c"
	}
	return runCommand(timeout, shell, flag, commandString)
}


// --- System Check Functions ---

func checkDiskEncryption() string {
	logger.Println("Checking disk encryption...")
	status := "Unknown"
	timeout := time.Duration(commandTimeoutSeconds) * time.Second

	switch runtime.GOOS {
	case "darwin":
		// fdesetup status might require root.
		stdout, stderr, rc := runCommand(timeout, "fdesetup", "status")
		if rc == 0 {
			if strings.Contains(stdout, "FileVault is On.") {
				status = "Enabled"
			} else if strings.Contains(stdout, "FileVault is Off.") {
				status = "Disabled"
			} else {
				status = "Could not determine (unexpected output)"
			}
		} else {
			status = fmt.Sprintf("Could not determine (rc: %d)", rc)
			if strings.Contains(stderr, "Authentication error") || strings.Contains(stderr, "root privileges") {
				status += " - fdesetup requires root privileges."
			} else if strings.Contains(stderr, "command not found") {
				status = "fdesetup command not found"
			}
		}
	case "windows":
		// Using PowerShell to check BitLocker status for the system drive.
		// ProtectionStatus: 0 = Off, 1 = On, 2 = Unknown
		cmd := "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"
		stdout, stderr, rc := runCommandWithShell(timeout, cmd)
		if rc == 0 {
			switch strings.TrimSpace(stdout) {
			case "1":
				status = "Enabled"
			case "0":
				status = "Disabled"
			default:
				status = fmt.Sprintf("Partial or unknown BitLocker state: %s", stdout)
			}
		} else {
			status = fmt.Sprintf("Could not determine BitLocker status (rc: %d)", rc)
			if strings.Contains(stderr, "privileges") || strings.Contains(stderr, "Access is denied") {
				status += " - Administrator privileges may be required."
			}
		}
	case "linux":
		// Basic check for LUKS or ZFS encryption. More robust checks might be needed.
		// Check for LUKS
		
		// stdoutLuks, _, rcLuks := runCommandWithShell(timeout, "lsblk -no NAME,TYPE,MOUNTPOINT,FSTYPE | grep -q crypt") // -q for quiet
		_, _, rcLuks := runCommandWithShell(timeout, "lsblk -no NAME,TYPE,MOUNTPOINT,FSTYPE | grep -q crypt") // -q for quiet	
		luksEncrypted := (rcLuks == 0)

		// Check for ZFS encryption on root (example, might need adjustment)
		// This assumes 'zfs' command is available and a 'root' dataset exists.
		stdoutZfs, _, rcZfs := runCommandWithShell(timeout, "zfs get -H -o value encryption rpool/ROOT 2>/dev/null || zfs get -H -o value encryption bpool/BOOT 2>/dev/null || zfs get -H -o value encryption $(df / --output=source | tail -n 1 | cut -d'[' -f1) 2>/dev/null")
		zfsEncrypted := false
		if rcZfs == 0 && stdoutZfs != "" && !strings.Contains(strings.ToLower(stdoutZfs), "off") && !strings.Contains(strings.ToLower(stdoutZfs), "none") {
			zfsEncrypted = true
		}
		
		if luksEncrypted && zfsEncrypted {
			status = "Enabled (LUKS & ZFS detected)"
		} else if luksEncrypted {
			status = "Enabled (LUKS detected)"
		} else if zfsEncrypted {
			status = "Enabled (ZFS encryption detected)"
		} else {
			status = "Likely Disabled (no common encryption patterns found)"
		}
	}
	logger.Printf("Disk encryption status: %s", status)
	return status
}

func checkOSUpdateStatus() string {
	logger.Println("Checking OS update status...")
	status := "Unknown"
	timeout := time.Duration(commandTimeoutSeconds) * time.Second

	switch runtime.GOOS {
	case "darwin":
		stdout, stderr, rc := runCommand(timeout*2, "softwareupdate", "-l") // Can take longer
		if rc == 0 {
			if strings.Contains(stdout, "No new software available.") || strings.Contains(stdout, "No software updates are available.") {
				status = "Up-to-date"
			} else if strings.Contains(stdout, "Software Update found") || strings.TrimSpace(stdout) != "" {
				status = "Updates available"
			} else {
				status = "Up-to-date (or no new updates listed)"
			}
		} else {
			status = fmt.Sprintf("Could not determine (rc: %d)", rc)
			if strings.Contains(strings.ToLower(stderr), "you are not an admin user") {
				status += " - Admin privileges may be required."
			}
		}
	case "windows":
		// This is a complex check. Using a PowerShell script to interact with the Windows Update Agent COM object.
		// This is a simplified version for brevity. Robust error handling in PowerShell is needed.
		// Consider last update install date as a proxy if COM object is too complex.
		// For simplicity, we'll check for pending reboots which often indicate updates.
		// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
		// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
		cmd := `
		$RebootRequiredReg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired';
		$PendingFileOpsReg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager';
		$UpdateSession = New-Object -ComObject Microsoft.Update.Session;
		$UpdateSearcher = $UpdateSession.CreateUpdateSearcher();
		try {
			$SearchResult = $UpdateSearcher.Search('IsInstalled=0 and Type_ = ''Software'''); # Type can be 'Software' or 'Driver'
			if ($SearchResult.Updates.Count -gt 0) {
				Write-Output "Updates available ($($SearchResult.Updates.Count) pending)";
			} elseif (Test-Path $RebootRequiredReg) {
				Write-Output "Updates installed, reboot pending";
			} elseif ((Get-ItemProperty -Path $PendingFileOpsReg -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) {
				Write-Output "Updates likely installed, reboot pending (PendingFileRenameOperations)";
			}
			 else {
				Write-Output "Likely up-to-date (no pending updates found via COM, no reboot required markers)";
			}
		} catch {
			Write-Output "Could not determine via COM object: $($_.Exception.Message)";
		}`
		stdout, stderr, rc := runCommandWithShell(timeout*2, cmd) // Update checks can be slow
		if rc == 0 && stdout != "" {
			status = stdout
		} else {
			status = fmt.Sprintf("Could not determine (rc: %d, stderr: %s)", rc, stderr)
		}

	case "linux":
		// Try common package managers
		var updatesCount = -1

		// Check for apt
		_, _, rcAptCmd := runCommand(timeout, "command", "-v", "apt")
		if rcAptCmd == 0 {
			// apt list --upgradable 2>/dev/null | grep -vc 'Listing...'
			// The grep -vc 'Listing...' is to exclude the header line from the count.
			// If only "Listing... Done" is present, count is 0. If updates, count > 0.
			stdout, _, rc := runCommandWithShell(timeout, "apt list --upgradable 2>/dev/null | grep -v '^Listing...' | wc -l")
			if rc == 0 {
				count, err := strconv.Atoi(strings.TrimSpace(stdout))
				if err == nil {
					updatesCount = count
				}
			}
		}

		// Check for yum if apt not found or failed
		if updatesCount == -1 {
			_, _, rcYumCmd := runCommand(timeout, "command", "-v", "yum")
			if rcYumCmd == 0 {
				stdout, _, rc := runCommandWithShell(timeout, "yum check-update -q | grep -v 'Obsoleting Packages' | wc -l")
				if rc == 0 || rc == 100 { // yum check-update exits 100 if updates are available, 0 if not
					count, err := strconv.Atoi(strings.TrimSpace(stdout))
					if err == nil {
						updatesCount = count
						if rc == 100 && count == 0 { // If exit code 100 but wc -l is 0, it means updates are available but not counted by wc -l (e.g. only obsoleting)
							updatesCount = 1 // Mark as at least one update
						}
					}
				}
			}
		}
		
		// Check for dnf if yum not found or failed
		if updatesCount == -1 {
			_, _, rcDnfCmd := runCommand(timeout, "command", "-v", "dnf")
			if rcDnfCmd == 0 {
				// dnf check-update -q --assumeno exits with 100 if updates are available, 0 if not.
				// We count lines of output that are not the metadata expiration line.
				stdout, _, rc := runCommandWithShell(timeout, "dnf check-update -q --assumeno | grep -v 'Last metadata expiration check' | wc -l")
				if rc == 0 || rc == 100 {
					 count, err := strconv.Atoi(strings.TrimSpace(stdout))
					 if err == nil {
						 updatesCount = count
						 if rc == 100 && count == 0 {
							 updatesCount = 1 // Mark as at least one update
						 }
					 }
				}
			}
		}

		if updatesCount > 0 {
			status = fmt.Sprintf("Updates available (%d packages)", updatesCount)
		} else if updatesCount == 0 {
			status = "Up-to-date"
		} else {
			status = "Could not determine or unknown package manager"
		}
	}
	logger.Printf("OS update status: %s", status)
	return status
}

func checkAntivirusPresence() AntivirusInfo {
	logger.Println("Checking antivirus presence...")
	av := AntivirusInfo{Presence: "Not found", Details: "No common AV indicators detected"}
	timeout := time.Duration(commandTimeoutSeconds) * time.Second

	switch runtime.GOOS {
	case "darwin":
		// Check common AV processes or bundle IDs (very basic)
		avPatterns := []string{"Sophos", "Little Snitch", "Malwarebytes", "Avast", "Bitdefender", "ESET", "Norton", "McAfee", "Kaspersky", "CrowdStrikeFalcon", "SentinelOne", "Intego"}
		cmdStr := fmt.Sprintf("ps aux | grep -E '%s' | grep -v grep", strings.Join(avPatterns, "|"))
		stdout, _, rc := runCommandWithShell(timeout, cmdStr)
		if rc == 0 && stdout != "" {
			av.Presence = "Detected"
			lines := strings.Split(stdout, "\n")
			av.Details = fmt.Sprintf("Found processes matching: %s", lines[0])
			break // Found via process, exit switch case
		}
		// Check common application paths
		commonPaths := []string{
			"/Applications/Sophos Home.app", "/Applications/Malwarebytes.app",
			"/Applications/Avast.app", "/Applications/Bitdefender.app",
			"/Library/Application Support/CrowdStrike", "/Applications/Falcon.app",
		}
		for _, path := range commonPaths {
			if _, err := os.Stat(path); err == nil {
				av.Presence = "Detected"
				av.Details = fmt.Sprintf("Found application at: %s", path)
				break
			}
		}

	case "windows":
		// Query Windows Security Center via PowerShell
		cmd := `Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName -ErrorAction SilentlyContinue`
		stdout, stderr, rc := runCommandWithShell(timeout, cmd)
		if rc == 0 && strings.TrimSpace(stdout) != "" {
			av.Presence = "Detected"
			av.Details = fmt.Sprintf("AV Product(s): %s", strings.TrimSpace(stdout))
		} else if strings.Contains(stderr, "Access is denied") || strings.Contains(stderr, "privileges") {
			av.Presence = "Unknown"
			av.Details = "Could not query SecurityCenter (Access Denied / Privileges required)"
		} else {
			// Fallback: Check common AV processes (less reliable)
			avProcesses := []string{"MsMpEng.exe", "NisSrv.exe", "savservice.exe", "bdagent.exe", "avgnt.exe", "avp.exe"} // Defender, Sophos, Bitdefender, AVG, Kaspersky
			tasklistOut, _, _ := runCommand(timeout, "tasklist")
			for _, proc := range avProcesses {
				if strings.Contains(strings.ToLower(tasklistOut), strings.ToLower(proc)) {
					av.Presence = "Detected (process check)"
					av.Details = fmt.Sprintf("Common AV process found: %s", proc)
					break
				}
			}
		}

	case "linux":
		// Common Linux AV process names (e.g., ClamAV, Sophos)
		avPatterns := []string{"clam[a|d]v", "sophosav", "savdid", "eset", "bitdefender", "avgd"}
		cmdStr := fmt.Sprintf("ps aux | grep -E '%s' | grep -v grep", strings.Join(avPatterns, "|"))
		stdout, _, rc := runCommandWithShell(timeout, cmdStr)
		if rc == 0 && stdout != "" {
			av.Presence = "Detected"
			lines := strings.Split(stdout, "\n")
			av.Details = fmt.Sprintf("Found processes matching: %s", lines[0])
		}
	}
	logger.Printf("Antivirus presence: %s, Details: %s", av.Presence, av.Details)
	return av
}

func checkInactivitySleepSettings() InactivitySleepSettings {
	logger.Println("Checking inactivity sleep settings...")
	settings := InactivitySleepSettings{
		ComplianceStatus:  fmt.Sprintf("Unknown (Target <= %d min)", maxAllowedSleepMinutes),
		ConfiguredMinutes: -1,
	}
	timeout := time.Duration(commandTimeoutSeconds) * time.Second

	switch runtime.GOOS {
	case "darwin":
		// pmset -g returns various settings, we grep for displaysleep
		// Output example: displaysleep         10 (display sleep timer)
		stdout, stderr, rc := runCommandWithShell(timeout, "pmset -g | grep displaysleep")
		if rc == 0 && stdout != "" {
			fields := strings.Fields(stdout) // Splits by whitespace
			if len(fields) >= 2 {
				minutes, err := strconv.Atoi(fields[1])
				if err == nil {
					settings.ConfiguredMinutes = minutes
				} else {
					logger.Printf("Could not parse displaysleep value from: %s", stdout)
				}
			}
		} else {
			logger.Printf("Could not get pmset displaysleep: rc=%d, stderr=%s", rc, stderr)
		}

	case "windows":
		// Checks "Turn off the display" (GUID: 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0) for AC power.
		// Result is in seconds.
		cmd := `
		try {
			$activeSchemeGuid = (powercfg /GETACTIVESCHEME) -replace '.*GUID: (.*?) .*', '$1';
			if ($activeSchemeGuid) {
				$powerCfgOutput = powercfg /Q $activeSchemeGuid SUB_VIDEO VIDEOIDLE;
				$acTimeoutLine = ($powerCfgOutput | Select-String -Pattern 'Current AC Power Setting Index');
				if ($acTimeoutLine -match '0x([0-9a-fA-F]+)') {
					$timeoutSeconds = [Convert]::ToInt32($Matches[1], 16);
					Write-Output ($timeoutSeconds / 60); # Convert to minutes
				} else { Write-Output 'ACSettingIndex not found in powercfg output'; }
			} else { Write-Output 'Could not parse active scheme GUID'; }
		} catch { Write-Output ('Error querying sleep settings: ' + $_.Exception.Message); }`

		stdout, stderr, rc := runCommandWithShell(timeout, cmd)
		if rc == 0 && stdout != "" {
			minutesStr := strings.TrimSpace(stdout)
			minutes, err := strconv.ParseFloat(minutesStr, 64)
			if err == nil {
				settings.ConfiguredMinutes = int(minutes)
			} else {
				logger.Printf("Could not parse sleep minutes from Windows: '%s', error: %v, stderr: %s", stdout, err, stderr)
				settings.ComplianceStatus = fmt.Sprintf("Could not parse value: %s", stdout)
			}
		} else {
			logger.Printf("Could not get Windows sleep settings: rc=%d, stderr=%s, stdout: %s", rc, stderr, stdout)
		}


	case "linux":
		// This is highly dependent on the Desktop Environment.
		// Trying GNOME first.
		stdoutGnome, _, rcGnome := runCommand(timeout, "gsettings", "get", "org.gnome.settings-daemon.plugins.power", "sleep-inactive-ac-timeout")
		if rcGnome == 0 && stdoutGnome != "" {
			seconds, err := strconv.Atoi(strings.TrimSpace(stdoutGnome))
			if err == nil {
				settings.ConfiguredMinutes = seconds / 60 // Value is in seconds
			}
		} else {
			// Add checks for KDE or other DEs if needed.
			// Example for KDE (might need specific kreadconfig5 path):
			// stdoutKde, _, rcKde := runCommandWithShell(timeout, "kreadconfig5 --group Daemon --key idleTime --file org.kde.Solid.PowerManagement.xml.zzz")
			// if rcKde == 0 ... parse ...
			logger.Println("Could not determine sleep settings for common Linux DEs (GNOME failed, others not implemented).")
			settings.ComplianceStatus = "Not determined for this Linux DE"
		}
	}

	if settings.ConfiguredMinutes != -1 {
		if settings.ConfiguredMinutes == 0 { // 0 often means "Never"
			settings.ComplianceStatus = fmt.Sprintf("Set to 'Never' (Value: %d min)", settings.ConfiguredMinutes)
		} else if settings.ConfiguredMinutes <= maxAllowedSleepMinutes {
			settings.ComplianceStatus = fmt.Sprintf("Compliant (Value: %d min)", settings.ConfiguredMinutes)
		} else {
			settings.ComplianceStatus = fmt.Sprintf("Non-compliant (Value: %d min, Target <= %d min)", settings.ConfiguredMinutes, maxAllowedSleepMinutes)
		}
	}
	logger.Printf("Inactivity sleep settings: %s (Configured: %d min)", settings.ComplianceStatus, settings.ConfiguredMinutes)
	return settings
}

// --- Core Logic ---

func getCurrentSystemState() SystemState {
	hostname, _ := os.Hostname()
	state := SystemState{
		Timestamp:               time.Now().UTC().Format(time.RFC3339),
		OS_Type:                 runtime.GOOS,
		Hostname:                hostname,
		DiskEncryption:          checkDiskEncryption(),
		OSUpdateStatus:          checkOSUpdateStatus(),
		AntivirusInfo:           checkAntivirusPresence(),
		InactivitySleepSettings: checkInactivitySleepSettings(),
	}
	return state
}

func loadPreviousState(filePath string) (*SystemState, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		logger.Println("Previous state file not found.")
		return nil, nil // No error, just no state
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading state file %s: %w", filePath, err)
	}

	var state SystemState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("error unmarshaling state file %s: %w", filePath, err)
	}
	return &state, nil
}

func saveCurrentState(filePath string, state SystemState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling state: %w", err)
	}
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing state file %s: %w", filePath, err)
	}
	return nil
}

func sendToAPI(data SystemState) bool {
	logger.Printf("Attempting to send data to API: %s", apiEndpoint)
	if apiEndpoint == "" || !strings.HasPrefix(apiEndpoint, "http") {
		logger.Println("API_ENDPOINT is not configured. Skipping API send.")
		fmt.Println("API_ENDPOINT not configured. Skipping API send.")
		return false
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Printf("Error marshaling data for API: %v", err)
		return false
	}

	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Printf("Error creating API request: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 20}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("Failed to send data to API: %v", err)
		fmt.Printf("Failed to send data to API: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	logger.Printf("API response status: %s", resp.Status)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Println("Data successfully sent to API.")
		fmt.Println("Data successfully sent to API.")
		return true
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	logger.Printf("API returned error status %s: %s", resp.Status, string(bodyBytes))
	fmt.Printf("API returned error status %s\n", resp.Status)
	return false
}

// statesAreEqual checks if two states are equal, ignoring timestamp and hostname.
func statesAreEqual(s1, s2 SystemState) bool {
	// Create copies for comparison, nullifying fields that always change or are identifiers
	c1 := s1
	c2 := s2
	c1.Timestamp = ""
	c2.Timestamp = ""
	c1.Hostname = ""
	c2.Hostname = ""

	// Marshal to JSON and compare strings for a deep comparison of relevant fields
	// This is a bit of a shortcut but effective for complex structs.
	// For very high performance, a field-by-field comparison would be better.
	b1, err1 := json.Marshal(c1)
	b2, err2 := json.Marshal(c2)

	if err1 != nil || err2 != nil {
		logger.Printf("Error marshaling states for comparison: %v, %v", err1, err2)
		return false // Treat as different if marshaling fails
	}
	return string(b1) == string(b2)
}

func setupLogger() {
	absLogFile, err := filepath.Abs(logFile)
	if err != nil {
		log.Fatalf("Failed to get absolute path for log file: %v", err)
	}

	file, err := os.OpenFile(absLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", absLogFile, err)
	}
	logger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	// Also log to stdout for interactive use
	// logger.SetOutput(io.MultiWriter(file, os.Stdout)) // If you want console output too
}


// --- Main Daemon Loop ---
func main() {
	setupLogger()
	logger.Println("System Utility Client started.")
	fmt.Println("System Utility Client started. Press Ctrl+C to stop.")
	absLogFilePath, _ := filepath.Abs(logFile)
	fmt.Printf("Logging to: %s\n", absLogFilePath)
	absStateFilePath, _ := filepath.Abs(stateFile)
	fmt.Printf("State file: %s\n", absStateFilePath)
	fmt.Printf("Checking system state every %d minutes.\n", checkIntervalMinutes)


	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initial state load
	previousState, err := loadPreviousState(stateFile)
	if err != nil {
		logger.Printf("Error loading initial state: %v. Continuing without previous state.", err)
		// previousState will be nil
	} else if previousState != nil {
		logger.Println("Loaded previous state.")
	} else {
		logger.Println("No previous state found. Will report current state on first successful check if it's different from an empty state (effectively always).")
	}


	ticker := time.NewTicker(time.Duration(checkIntervalMinutes) * time.Minute)
	defer ticker.Stop()

	// Perform an initial check immediately
	performCheck := func() {
		logger.Println("--- Starting new check cycle ---")
		currentState := getCurrentSystemState()

		// If previousState is nil (e.g., first run or error loading),
		// we consider it a change to report the initial state.
		changed := true
		if previousState != nil {
			changed = !statesAreEqual(*previousState, currentState)
		}


		if changed {
			logger.Println("System state has changed or is initial check. Reporting to API.")
			fmt.Println("System state has changed or is initial check. Reporting to API...")
			if sendToAPI(currentState) {
				if err := saveCurrentState(stateFile, currentState); err != nil {
					logger.Printf("Error saving current state after successful API send: %v", err)
				} else {
					logger.Println("Current state saved.")
					previousState = &currentState // Update in-memory previous state
				}
			} else {
				logger.Println("Failed to send data to API. State not updated, will retry next cycle.")
				fmt.Println("Failed to send data to API. Will retry next cycle.")
			}
		} else {
			logger.Println("No change in system state detected.")
			fmt.Println("No change in system state detected.")
			// Optionally, save current state even if no change to update timestamp in state file
			if err := saveCurrentState(stateFile, currentState); err != nil {
				logger.Printf("Error saving current state (no change): %v", err)
			}
			previousState = &currentState
		}
		logger.Printf("--- Check cycle finished. Waiting for next interval. ---")
		fmt.Printf("Next check in approximately %d minutes. Press Ctrl+C to stop.\n", checkIntervalMinutes)
	}

	performCheck() // Initial check

	for {
		select {
		case <-ticker.C:
			performCheck()
		case sig := <-sigChan:
			logger.Printf("Received signal: %v. Shutting down.", sig)
			fmt.Println("\nSystem Utility Client stopped.")
			return
		}
	}
}
