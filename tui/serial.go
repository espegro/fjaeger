// Package main implements the Fjaeger terminal (TUI) controller.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	mu         sync.Mutex
	port       serial.Port
	needsSync  bool
	promptTail []byte
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
	if err := port.SetReadTimeout(readTimeout); err != nil {
		_ = port.Close()
		return nil, err
	}
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
	return d.readUntilDeadline(time.Now().Add(execTimeout))
}

func (d *Device) readUntilDeadline(deadline time.Time) (string, error) {
	var buf bytes.Buffer
	buf.Write(d.promptTail)
	d.needsSync = true
	for time.Now().Before(deadline) {
		tmp := make([]byte, 256)
		n, err := d.port.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.Contains(buf.Bytes(), []byte(prompt)) {
				d.needsSync = false
				d.promptTail = nil
				return buf.String(), nil
			}
		}
		if err != nil {
			d.savePromptTail(buf.Bytes())
			return "", fmt.Errorf("serial read: %w", err)
		}
	}
	d.savePromptTail(buf.Bytes())
	return "", errors.New("timed out waiting for device prompt; command may still be running")
}

// Keep only a possible partial prompt, never the previous command's output.
func (d *Device) savePromptTail(data []byte) {
	d.promptTail = nil
	for n := len(prompt) - 1; n > 0; n-- {
		if bytes.HasSuffix(data, []byte(prompt[:n])) {
			d.promptTail = append([]byte(nil), data[len(data)-n:]...)
			return
		}
	}
}

func (d *Device) synchronize() error {
	if d.needsSync {
		if _, err := d.readUntilPrompt(); err != nil {
			return fmt.Errorf("waiting for previous command to finish: %w", err)
		}
	}
	return nil
}

// Exec sends one command line and returns the device reply (prompt removed).
func (d *Device) Exec(cmd string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.port == nil {
		return "", errors.New("not connected")
	}
	// Drain a timed-out command before sending anything new. Its late reply
	// must never be mistaken for the response to this command.
	if err := d.synchronize(); err != nil {
		return "", err
	}
	if err := d.port.ResetInputBuffer(); err != nil {
		return "", err
	}

	d.needsSync = true
	line := []byte(cmd + "\r\n")
	if n, err := d.port.Write(line); err != nil {
		return "", err
	} else if n != len(line) {
		return "", io.ErrShortWrite
	}
	raw, err := d.readUntilPrompt()
	if err != nil {
		return "", err
	}
	reply := cleanReply(raw)
	for _, line := range strings.Split(reply, "\n") {
		if line == "ERR" || strings.HasPrefix(line, "ERR ") {
			return reply, errors.New(line)
		}
	}
	return reply, nil
}

// Reset sends a reboot command and drops the connection.
func (d *Device) Reset(cmd string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.port == nil {
		return errors.New("not connected")
	}
	if err := d.synchronize(); err != nil {
		return err
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
