// Package main implements the Fjaeger terminal (TUI) controller.
package main

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
)

const (
	prompt      = "fjaeger> "
	defaultBaud = 115200
	readTimeout = 350 * time.Millisecond
	execTimeout = 15 * time.Second
)

// Device wraps a serial connection to the Fjaeger console.
type Device struct {
	mu   sync.Mutex
	port serial.Port
}

// Connect opens the serial port at path.
func Connect(path string, baud int) (*Device, error) {
	if baud <= 0 {
		baud = defaultBaud
	}
	port, err := serial.Open(path, &serial.Mode{BaudRate: baud})
	if err != nil {
		return nil, err
	}
	port.SetReadTimeout(readTimeout)
	return &Device{port: port}, nil
}

// Connected reports whether the device is connected.
func (d *Device) Connected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.port != nil
}

// Disconnect closes the port.
func (d *Device) Disconnect() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.port != nil {
		_ = d.port.Close()
		d.port = nil
	}
}

// readUntilPrompt reads bytes until the console prompt appears.
func (d *Device) readUntilPrompt() (string, error) {
	var buf bytes.Buffer
	deadline := time.Now().Add(execTimeout)
	for time.Now().Before(deadline) {
		tmp := make([]byte, 256)
		n, err := d.port.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.Contains(buf.Bytes(), []byte(prompt)) {
				break
			}
			continue
		}
		if err != nil {
			// Non-fatal (timeout); keep trying until the deadline elapses.
			continue
		}
	}
	return buf.String(), nil
}

// Exec sends one command line and returns the device reply (prompt removed).
func (d *Device) Exec(cmd string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.port == nil {
		return "", errors.New("not connected")
	}
	// Drop anything left over from a previous interaction.
	_ = d.port.ResetInputBuffer()

	if _, err := d.port.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	raw, err := d.readUntilPrompt()
	if err != nil {
		return "", err
	}
	return cleanReply(raw), nil
}

// Reset sends a reboot command and drops the connection.
func (d *Device) Reset(cmd string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.port == nil {
		return errors.New("not connected")
	}
	_, _ = d.port.Write([]byte(cmd + "\r\n"))
	time.Sleep(500 * time.Millisecond)
	_ = d.port.Close()
	d.port = nil
	return nil
}

// cleanReply strips the echoed command line and the trailing prompt. The
// echoed copy of an inline secret is removed so it does not appear on screen.
func cleanReply(raw string) string {
	out := raw
	if i := strings.IndexAny(out, "\r\n"); i >= 0 {
		out = out[i:]
	}
	out = strings.ReplaceAll(out, "\r", "")
	out = strings.TrimSuffix(out, "\n")
	out = strings.TrimSuffix(out, prompt)
	return strings.TrimSpace(out)
}
