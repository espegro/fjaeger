package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"go.bug.st/serial"
)

type fakePort struct {
	serial.Port
	reply   string
	err     error
	writes  int
	onWrite func()
}

func (p *fakePort) Read(b []byte) (int, error) {
	n := copy(b, p.reply)
	p.reply = p.reply[n:]
	return n, p.err
}
func (p *fakePort) Write(b []byte) (int, error) {
	p.writes++
	if p.onWrite != nil {
		p.onWrite()
	}
	return len(b), nil
}
func (p *fakePort) ResetInputBuffer() error { return nil }

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

func TestLateReplyDrainedBeforeNextCommand(t *testing.T) {
	p := &fakePort{reply: "OLD\r\nOK old\r\nfja"}
	d := Device{port: p}
	_, err := d.readUntilDeadline(time.Now().Add(time.Millisecond))
	if err == nil {
		t.Fatal("expected timeout")
	}
	// The prompt itself straddles the timeout. Nothing may be discarded
	// until its remaining bytes have been consumed.
	p.reply = "eger> "
	p.onWrite = func() {
		if p.reply != "" {
			t.Fatal("wrote before consuming old prompt")
		}
		p.reply = "STATUS\r\nOK new\r\nfjaeger> "
	}
	reply, err := d.Exec("STATUS")
	if err != nil || reply != "OK new" || p.writes != 1 {
		t.Fatalf("reply=%q err=%v writes=%d", reply, err, p.writes)
	}
}

func TestNoWriteWhilePreviousCommandUnfinished(t *testing.T) {
	p := &fakePort{reply: "partial"}
	d := Device{port: p}
	_, err := d.readUntilDeadline(time.Now().Add(time.Millisecond))
	if err == nil {
		t.Fatal("expected timeout")
	}
	p.err = io.EOF
	if _, err := d.Exec("STATUS"); err == nil {
		t.Fatal("expected sync error")
	}
	if err := d.Reset("REBOOT"); err == nil {
		t.Fatal("expected sync error")
	}
	if p.writes != 0 {
		t.Fatal("sent command while response incomplete")
	}
}
