package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// CLI mode: run one command against the device, e.g.
	//   fjaeger-tui /dev/ttyACM0 STATUS
	//   fjaeger-tui /dev/ttyACM0 CREDS LIST
	if len(os.Args) >= 3 {
		if err := cliRun(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 {
		fmt.Fprintln(os.Stderr, "usage: fjaeger-tui [serialport COMMAND [args...]]")
		os.Exit(2)
	}

	m := model{}
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
