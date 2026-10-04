package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Status is the parsed form of the STATUS reply.
type Status struct {
	Version      string
	State        string // "unlocked" | "locked"
	Disk         string // "unlocked" | "locked"
	PassBlocked  bool
	PassFail     int
	PinFail      int
	PUKFail      int
	DiskFail     int
	FlushPending bool
	PUK          string
	Profile      int
	Profiles     int
	Timeout      int
}

// ParseStatus turns a STATUS reply into a Status struct.
func ParseStatus(reply string) Status {
	s := Status{Profile: -1, Timeout: -1}
	vals := map[string]string{}
	for _, line := range strings.Split(reply, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ':'); i > 0 {
			key := strings.TrimSpace(line[:i])
			val := strings.TrimSpace(line[i+1:])
			vals[key] = val
		}
	}
	s.Version = vals["version"]
	s.State = vals["state"]
	s.Disk = vals["disk"]
	s.PassBlocked = vals["pass_blocked"] == "yes"
	s.PassFail = atoi(vals["pass_fail"])
	s.PinFail = atoi(vals["ctap_pin_fail"])
	s.PUKFail = atoi(vals["puk_fail"])
	s.DiskFail = atoi(vals["disk_fail"])
	s.FlushPending = strings.HasPrefix(vals["disk_flush_pending"], "yes")
	s.PUK = vals["puk"]
	s.Profile = atoi(vals["active_profile"])
	s.Profiles = atoi(vals["profiles"])
	if v := atoi(strings.TrimSuffix(vals["timeout"], "s")); v >= 0 {
		s.Timeout = v
	}
	return s
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}

// Profile is one line of the PROFILE LIST reply.
type Profile struct {
	ID     int
	Name   string
	Count  int
	Active bool
}

var profileRE = regexp.MustCompile(`^profile\s+(\d+):\s*(.*?)\s*\[(\d+)\](?:\s+\(active\))?$`)

// ParseProfiles turns a PROFILE LIST reply into a slice of Profile.
func ParseProfiles(reply string) []Profile {
	var out []Profile
	for _, line := range strings.Split(reply, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "profile ") {
			continue
		}
		m := profileRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[2])
		out = append(out, Profile{
			ID:     atoi(m[1]),
			Name:   name,
			Count:  atoi(m[3]),
			Active: strings.Contains(line, "(active)"),
		})
	}
	return out
}

// Cred is one line of the CREDS LIST reply.
type Cred struct {
	ID          string
	Type        string
	Application string
	Resident    bool
	Fingerprint string
}

var credRE = regexp.MustCompile(`^\[\d+\]\s+type=(\S+)\s+application=(\S+)\s+resident=(yes|no)\s+fp=(\S+)\s+id=(\S+)`)

// ParseCreds turns a CREDS LIST reply into a slice of Cred.
func ParseCreds(reply string) []Cred {
	var out []Cred
	for _, line := range strings.Split(reply, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		m := credRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Cred{
			ID:          m[5],
			Type:        m[1],
			Application: m[2],
			Resident:    m[3] == "yes",
			Fingerprint: m[4],
		})
	}
	return out
}
