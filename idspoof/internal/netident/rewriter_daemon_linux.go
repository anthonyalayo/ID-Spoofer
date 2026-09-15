//go:build linux

// rewriter_daemon_linux.go — The NFQUEUE rewriter must outlive the CLI
// process: the kernel keeps diverting SYN packets to queue 42 as long as
// the iptables rule exists, and with no userland dequeuer the kernel's
// queue-lifetime timer drops them, killing every new TCP connection.
//
// apply therefore spawns a detached helper process — the same binary
// re-exec'd as the hidden `idspoof __rewriter` subcommand — which binds
// the queue and rewrites packets until signalled. restore terminates it.
// Liveness is tracked via a pid file in the state directory.

package netident

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// rewriterPidFileName is the pid file written by the helper process.
	// Format: "<pid>\t<persona>\n"
	rewriterPidFileName = "rewriter.pid"

	// rewriterLogFileName captures the helper's stdout/stderr for debugging.
	rewriterLogFileName = "rewriter.log"

	// rewriterReadyTimeout bounds how long apply waits for the helper to
	// bind the queue and advertise itself.
	rewriterReadyTimeout = 5 * time.Second

	// rewriterStopTimeout bounds how long we wait for SIGTERM to land.
	rewriterStopTimeout = 3 * time.Second
)

// rewriterInfo is the parsed pid file.
type rewriterInfo struct {
	PID     int
	Persona PersonaType
}

// readRewriterInfo parses the pid file. Returns (_, false) when the file is
// missing or malformed.
func readRewriterInfo(pidFile string) (rewriterInfo, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return rewriterInfo{}, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return rewriterInfo{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return rewriterInfo{}, false
	}
	info := rewriterInfo{PID: pid, Persona: PersonaWindows}
	if len(fields) > 1 {
		info.Persona = PersonaType(fields[1])
	}
	return info, true
}

// rewriterProcAlive reports whether pid points at a live rewriter process.
// The /proc/<pid>/cmdline check guards against PID reuse: a stale pid file
// pointing at an unrelated process that recycled the PID must not be
// treated (or signalled) as ours.
func rewriterProcAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(bytes.ReplaceAll(data, []byte{0}, []byte{0x20})), "__rewriter")
}

// RewriterStatus reports the rewriter daemon's state for status displays.
func RewriterStatus(stateDir string) (pid int, persona string, alive bool) {
	if stateDir == "" {
		return 0, "", false
	}
	info, ok := readRewriterInfo(filepath.Join(stateDir, rewriterPidFileName))
	if !ok {
		return 0, "", false
	}
	alive = rewriterProcAlive(info.PID)
	return info.PID, string(info.Persona), alive
}

// SpawnRewriterDaemon ensures a live rewriter daemon for the given persona.
//
//   - A live daemon for the same persona is reused (idempotent re-apply).
//   - A live daemon for a different persona is stopped and replaced.
//   - A stale pid file is cleaned up.
//
// The helper is spawned in its own session (Setsid) so it survives the CLI
// exiting and terminal hangups. Returns the live daemon's PID.
func SpawnRewriterDaemon(stateDir string, persona PersonaType) (int, error) {
	if stateDir == "" {
		return 0, fmt.Errorf("state directory not configured; cannot spawn rewriter daemon")
	}
	pidFile := filepath.Join(stateDir, rewriterPidFileName)

	// Handle any existing daemon first.
	if info, ok := readRewriterInfo(pidFile); ok {
		switch {
		case rewriterProcAlive(info.PID) && info.Persona == persona:
			return info.PID, nil // already running for this persona.
		case rewriterProcAlive(info.PID):
			if err := killRewriterProcess(info.PID); err != nil {
				return 0, fmt.Errorf("stopping previous rewriter (PID %d): %w", info.PID, err)
			}
			os.Remove(pidFile)
		default:
			os.Remove(pidFile) // stale pid file.
		}
	}

	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolving self path: %w", err)
	}

	cmd := exec.Command(self, "__rewriter", "--persona", string(persona), "--state-dir", stateDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Truncate: each daemon generation gets a fresh log. Appending left
	// stale errors from earlier runs in the tail and could surface an
	// old last line in the spawn-failure diagnostic below.
	logFile, err := os.OpenFile(filepath.Join(stateDir, rewriterLogFileName),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("opening rewriter log: %w", err)
	}
	devNull, nerr := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if nerr == nil {
		cmd.Stdin = devNull
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("starting rewriter process: %w", err)
	}
	if devNull != nil {
		devNull.Close()
	}

	// Wait for the helper to bind the queue and advertise itself.
	startWait := time.Now()
	for {
		if info, ok := readRewriterInfo(pidFile); ok &&
			info.PID == cmd.Process.Pid && rewriterProcAlive(info.PID) {
			logFile.Close()
			return info.PID, nil
		}
		if time.Since(startWait) >= rewriterReadyTimeout {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Failure path: capture diagnostics, tear down, remove the queue rule.
	var lastLog string
	if cmd.Process != nil {
		cmd.Process.Kill()
		_ = cmd.Wait()
	}
	logFile.Close()
	if data, err := os.ReadFile(filepath.Join(stateDir, rewriterLogFileName)); err == nil {
		if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) > 0 {
			lastLog = lines[len(lines)-1]
		}
	}
	os.Remove(pidFile)
	return 0, fmt.Errorf("rewriter did not bind NFQUEUE within %s (last log: %q)",
		rewriterReadyTimeout, lastLog)
}

// StopRewriterDaemon terminates the rewriter daemon, if one is running.
// Returns the PID of the stopped daemon, or 0 if none was running.
func StopRewriterDaemon(stateDir string) (int, error) {
	if stateDir == "" {
		return 0, nil
	}
	pidFile := filepath.Join(stateDir, rewriterPidFileName)
	info, ok := readRewriterInfo(pidFile)
	if !ok || !rewriterProcAlive(info.PID) {
		os.Remove(pidFile) // stale file, if any.
		return 0, nil
	}
	if err := killRewriterProcess(info.PID); err != nil {
		return info.PID, fmt.Errorf("stopping rewriter (PID %d): %w", info.PID, err)
	}
	os.Remove(pidFile)
	return info.PID, nil
}

// killRewriterProcess sends SIGTERM and escalates to SIGKILL after a
// grace period.
func killRewriterProcess(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(rewriterStopTimeout)
	for rewriterProcAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if rewriterProcAlive(pid) {
		return syscall.Kill(pid, syscall.SIGKILL)
	}
	return nil
}

// RunRewriterDaemon runs the NFQUEUE rewriter in the foreground until
// SIGTERM/SIGINT. Entry point of the hidden `idspoof __rewriter`
// subcommand; it is spawned detached by apply and outlives the CLI.
func RunRewriterDaemon(persona PersonaType, stateDir string) error {
	if stateDir == "" {
		return fmt.Errorf("state directory not configured")
	}
	pidFile := filepath.Join(stateDir, rewriterPidFileName)

	// Refuse to double-bind the queue if another live daemon owns it.
	if info, ok := readRewriterInfo(pidFile); ok && rewriterProcAlive(info.PID) {
		return fmt.Errorf("rewriter already running (PID %d, persona %s)", info.PID, info.Persona)
	}

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}

	// The helper process has no knowledge of the CLI's in-memory state —
	// seed the persona before the rewriter goroutine reads it.
	activePersona.Store(persona)

	r := NewNFQueueRewriter(nfqueueNum)
	if err := r.Start(); err != nil {
		return fmt.Errorf("binding NFQUEUE %d: %w", nfqueueNum, err)
	}

	// Advertise liveness so apply/restore/status can find us.
	if err := os.WriteFile(pidFile,
		[]byte(fmt.Sprintf("%d\t%s\n", os.Getpid(), persona)), 0o644); err != nil {
		r.Stop()
		return fmt.Errorf("writing pid file: %w", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	<-sigs

	r.Stop()
	os.Remove(pidFile)
	return nil
}
