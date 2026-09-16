//go:build linux

package netident

import (
	"fmt"
	"os/exec"
	"strings"
)

// Chain name used for our rules so we can cleanly add/remove without
// disturbing existing firewall config.
const chainName = "IDSPOOF_NETEMU"

// applyIPTables creates a mangle chain with rules that make outgoing packets
// match the target OS persona:
//   - TTL set to persona value (128 for Windows, 64 for macOS/iOS)
//   - MSS clamped to 1460 on SYN packets
func applyIPTables(p *Persona) error {
	// Create our chain (ignore error if already exists).
	exec.Command("iptables", "-t", "mangle", "-N", chainName).Run()

	// Flush our chain to start clean.
	if err := run("iptables", "-t", "mangle", "-F", chainName); err != nil {
		return fmt.Errorf("flush chain: %w", err)
	}

	// Add rules to our chain.
	rules := [][]string{
		// TTL → 128 on all outgoing.
		{"-t", "mangle", "-A", chainName, "-j", "TTL", "--ttl-set", fmt.Sprintf("%d", p.TTL)},
		// MSS → 1460 on SYN packets (matches Windows Ethernet default).
		{"-t", "mangle", "-A", chainName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", p.MSS)},
	}

	for _, r := range rules {
		if err := run("iptables", r...); err != nil {
			return fmt.Errorf("adding rule %v: %w", r, err)
		}
	}

	// Jump from POSTROUTING to our chain (add only if not already
	// present). Check the exact global jump, not any jump to the chain:
	// a stale owner-scoped jump left by a crashed `serve --owner` must
	// not make a plain apply inherit the old single-user scoping.
	if exec.Command("iptables", "-t", "mangle", "-C", "POSTROUTING", "-j", chainName).Run() != nil {
		if err := run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", chainName); err != nil {
			return fmt.Errorf("adding jump: %w", err)
		}
	}

	return nil
}

// removeIPTables cleans up all iptables rules added by applyIPTables.
func removeIPTables() error {
	// Remove every jump into our chain from POSTROUTING — the plain global
	// jump as well as any owner-scoped jump added by `serve --owner`.
	if out, err := exec.Command("iptables", "-t", "mangle", "-S", "POSTROUTING").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || fields[1] != "POSTROUTING" {
				continue
			}
			if !strings.Contains(line, chainName) {
				continue
			}
			args := append([]string{"-t", "mangle", "-D", "POSTROUTING"}, fields[2:]...)
			exec.Command("iptables", args...).Run()
		}
	}

	// Flush and delete our chain.
	exec.Command("iptables", "-t", "mangle", "-F", chainName).Run()
	exec.Command("iptables", "-t", "mangle", "-X", chainName).Run()

	// Backward compat: also clean up old v2.0.0 chain name if present.
	exec.Command("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "IDSPOOF_WINEMU").Run()
	exec.Command("iptables", "-t", "mangle", "-F", "IDSPOOF_WINEMU").Run()
	exec.Command("iptables", "-t", "mangle", "-X", "IDSPOOF_WINEMU").Run()

	return nil
}

// ScopeToOwner narrows the mangle chain to one user's traffic: the global
// POSTROUTING jump is replaced with a uid-owner-scoped jump, so packets
// from every other user pass through unmodified.
func ScopeToOwner(owner string) error {
	// Drop the global jump (may already be gone).
	exec.Command("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", chainName).Run()
	// Drop owner-scoped jumps a previous crashed session left behind:
	// only a clean restore removes them, so a restart under a different
	// owner would otherwise keep rewriting the old owner's traffic too.
	if out, err := exec.Command("iptables", "-t", "mangle", "-S", "POSTROUTING").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || fields[1] != "POSTROUTING" {
				continue
			}
			if !strings.Contains(line, chainName) || !strings.Contains(line, "-m owner") {
				continue
			}
			args := append([]string{"-t", "mangle", "-D", "POSTROUTING"}, fields[2:]...)
			exec.Command("iptables", args...).Run()
		}
	}
	// Idempotent: the scoped jump may already be in place from a previous start.
	if err := exec.Command("iptables", "-t", "mangle", "-C", "POSTROUTING",
		"-m", "owner", "--uid-owner", owner, "-j", chainName).Run(); err == nil {
		return nil
	}
	// iptables resolves the user name to a UID at install time; a missing
	// user is an error.
	return run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-m", "owner", "--uid-owner", owner, "-j", chainName)
}

// jumpExists checks if POSTROUTING already has a jump to our chain.
func jumpExists() bool {
	out, err := exec.Command("iptables", "-t", "mangle", "-S", "POSTROUTING").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), chainName)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
