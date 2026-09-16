package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/config"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/spoofer"
	"github.com/spf13/cobra"
)

// serveCmd is the single-process "managed" mode: apply the netident
// persona, run the NFQUEUE rewriter in the foreground, and restore
// everything when the process exits. It is meant to be supervised by
// systemd (Type=simple + Restart=on-failure): a crash or SIGKILL is
// restarted (re-apply is idempotent), and every clean exit tears the
// persona down, so no state is ever left behind.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Apply the selected spoofing operations in one foreground process, restore everything on exit",
	Long: `serve owns the whole spoofing lifecycle in one foreground process:

  1. applies the selected operations — MAC, network persona, sysinfo
     (all three by default, like apply; pass individual flags to
     restrict, e.g. --netident for persona + rewriter only)
  2. runs the NFQUEUE rewriter in the foreground (with --netident)
  3. on SIGTERM/SIGINT (systemctl stop, Ctrl-C), restores the system

Run it under a supervisor: after a crash or SIGKILL the supervisor
restarts it and the re-apply is idempotent; a clean stop leaves the
machine in its original state.`,
	RunE: runServe,
}

var serveOpts struct {
	persona  string
	owner    string
	mac      bool
	netident bool
	sysinfo  bool
}

func init() {
	f := serveCmd.Flags()
	f.StringVar(&serveOpts.persona, "persona", "windows", "Network persona to project (windows, macos, ios, linux, android)")
	f.StringVar(&serveOpts.owner, "owner", "", "Scope the mangle chain to one user's traffic (iptables -m owner --uid-owner); default: all users")
	f.BoolVar(&serveOpts.mac, "mac", false, "Spoof MAC addresses")
	f.BoolVar(&serveOpts.netident, "netident", false, "Apply network persona (TCP/IP stack, DHCP, NFQUEUE)")
	f.BoolVar(&serveOpts.sysinfo, "sysinfo", false, "Generate fake system hardware profile")
}

func runServe(cmd *cobra.Command, args []string) error {
	pt := parsePersonaType(serveOpts.persona)
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = config.DefaultStateDir
	}

	// Take over the queue: stop whatever a previous session left running
	// (a detached helper from a manual `apply`, or an older serve that
	// died without restoring). This process becomes the sole owner.
	if pid, err := netident.StopRewriterDaemon(stateDir); err == nil && pid > 0 {
		if !cfg.Quiet {
			fmt.Printf("stopped previous rewriter (PID %d)\n", pid)
		}
	}

	// Operation selection, same convention as apply: with no operation
	// flags all three run; passing any restricts to those selected.
	runMAC, runNetIdent, runSysInfo := selectOps(serveOpts.mac, serveOpts.netident, serveOpts.sysinfo)

	// Start the rewriter engine BEFORE applying the stack: the apply
	// below (NoDaemon) then sees a live rewriter for the matching
	// persona and stays quiet instead of warning that the queue has
	// no dequeuer yet. Binding before the iptables NFQUEUE rule exists
	// is safe — nothing is diverted to the queue until the rule lands.
	var rw *netident.NFQueueRewriter
	if runNetIdent {
		var err error
		rw, err = netident.PrepareRewriterDaemon(pt, stateDir, "serve")
		if err != nil {
			return fmt.Errorf("rewriter: %w", err)
		}
	}

	// Install the selected stack without forking: this process runs the
	// rewriter itself, so no helper is spawned.
	applyResults := orch.Apply(spoofer.Options{
		MAC:         runMAC,
		NetIdent:    runNetIdent,
		SysInfo:     runSysInfo,
		PersonaType: pt,
		NoDaemon:    true,
		Quiet:       cfg.Quiet,
	})
	for _, r := range applyResults {
		if !r.Success {
			// Nothing usable was installed; unwind what we touched.
			netident.FinishRewriterDaemon(rw, stateDir)
			orch.Restore(spoofer.Options{MAC: runMAC, NetIdent: runNetIdent, SysInfo: runSysInfo, Quiet: true})
			return fmt.Errorf("apply failed; system state restored")
		}
	}
	printResults(applyResults)

	// Optionally narrow the mangle chain to one user's traffic.
	if serveOpts.owner != "" && runNetIdent {
		if err := netident.ScopeToOwner(serveOpts.owner); err != nil {
			netident.FinishRewriterDaemon(rw, stateDir)
			orch.Restore(spoofer.Options{MAC: runMAC, NetIdent: runNetIdent, SysInfo: runSysInfo, Quiet: true})
			return fmt.Errorf("scoping to owner %q: %v; system state restored", serveOpts.owner, err)
		}
		if !cfg.Quiet {
			fmt.Printf("mangle chain scoped to user %q\n", serveOpts.owner)
		}
	} else if serveOpts.owner != "" {
		if !cfg.Quiet {
			fmt.Println("note: --owner scopes the mangle chain, which requires --netident")
		}
	}

	if !cfg.Quiet && runNetIdent {
		fmt.Printf("rewriter running as PID %d — SIGTERM or Ctrl-C stops it and restores the system\n", os.Getpid())
	}

	// Wait for the supervisor's stop signal (systemctl stop, Ctrl-C);
	// every exit path restores the machine below.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigs
	if !cfg.Quiet {
		fmt.Printf("received %s; restoring\n", sig)
	}

	if rw != nil {
		netident.FinishRewriterDaemon(rw, stateDir)
	}

	// Every exit path restores the machine.
	restoreResults := orch.Restore(spoofer.Options{MAC: runMAC, NetIdent: runNetIdent, SysInfo: runSysInfo, Quiet: cfg.Quiet})
	printResults(restoreResults)
	if !cfg.Quiet {
		fmt.Println("restored; system state clean")
	}
	return nil
}
