package main

import (
	"errors"
	"go.bug.st/serial"
	"io"
	"strings"
	"testing"
	"time"
)

type fakePort struct {
	serial.Port
	reply string
	err   error
}

func (p *fakePort) Read(b []byte) (int, error) {
	n := copy(b, p.reply)
	p.reply = p.reply[n:]
	return n, p.err
}
func (p *fakePort) Write(b []byte) (int, error) { return len(b), nil }
func (p *fakePort) ResetInputBuffer() error     { return nil }

func TestExecReplies(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		readErr     error
		wantError   bool
	}{
		{"success", "STATUS\r\nOK ready\r\nfjaeger> ", nil, false},
		{"rejected", "DISK UNLOCK secret\r\nERR wrong PIN\r\nfjaeger> ", nil, true},
		{"disconnected", "", io.EOF, true},
		{"partial disconnect", "STATUS\r\nOK", io.EOF, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Device{port: &fakePort{reply: tc.reply, err: tc.readErr}}
			reply, err := d.Exec("STATUS")
			if (err != nil) != tc.wantError {
				t.Fatalf("reply=%q err=%v", reply, err)
			}
			if strings.Contains(reply, "secret") {
				t.Fatal("echoed secret leaked")
			}
		})
	}
}
func TestPromptTimeout(t *testing.T) {
	d := Device{port: &fakePort{reply: "partial response"}}
	_, err := d.readUntilDeadline(time.Now().Add(time.Millisecond))
	if err == nil {
		t.Fatal("missing prompt accepted")
	}
}
func TestReadErrorPreserved(t *testing.T) {
	d := Device{port: &fakePort{err: io.EOF}}
	_, err := d.readUntilPrompt()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v", err)
	}
}
