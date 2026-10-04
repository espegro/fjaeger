package main

import (
	"fmt"
	"strings"
)

// cliRun connects to a device and executes one console command, printing the
// raw reply. Useful for scripting and for the live device test.
func cliRun(port string, args []string) error {
	cmd := strings.Join(args, " ")
	dev, err := Connect(port, defaultBaud)
	if err != nil {
		return err
	}
	defer dev.Disconnect()

	// Consume the connect banner so the reply below is not polluted.
	dev.Exec("")
	reply, err := dev.Exec(cmd)
	if err != nil {
		return err
	}
	fmt.Print(reply)
	if reply != "" && !strings.HasSuffix(reply, "\n") {
		fmt.Println()
	}
	return nil
}
