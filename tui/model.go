package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"go.bug.st/serial"
)

// ---------------------------------------------------------------- messages

type tickMsg time.Time
type statusMsg Status
type resultMsg string
type consoleResultMsg string
type errMsg error
type connMsg *Device
type listProfilesMsg []Profile
type listCredsMsg []Cred
type diskMsg Status

type listKind int

const (
	listProfiles listKind = iota
	listCreds
)

// ---------------------------------------------------------------- model

type screen int

const (
	scrConnect screen = iota
	scrMain
	scrPrompt
	scrShow
	scrConsole
	scrList
	scrDisk
)

type fieldDef struct {
	prompt string
	secret bool
}

type kind int

const (
	kCmd      kind = iota
	kStatus
	kConsole
	kReset
	kSep
	kQuit
	kProfiles
	kCreds
	kDisk
)

type act struct {
	kind   kind
	label  string
	fields []fieldDef
	askYes bool
	build  func([]string) string
}

var menu = []act{
	{kStatus, "Status (live)", nil, false, nil},
	{kind: kSep},
	{kCmd, "Lock device", nil, false, func(v []string) string { return "LOCK" }},
	{kCmd, "Unlock device", []fieldDef{{"Passphrase", true}}, false, func(v []string) string { return "UNLOCK " + v[0] }},
	{kCmd, "Unlock via PUK", []fieldDef{{"Recovery PUK", true}}, false, func(v []string) string { return "UNLOCKPUK " + v[0] }},
	{kCmd, "Set unlock passphrase", []fieldDef{{"New passphrase", true}}, false, func(v []string) string { return "SETPASS " + v[0] }},
	{kCmd, "Set CTAP2 PIN", []fieldDef{{"New CTAP2 PIN", true}}, false, func(v []string) string { return "SETPIN " + v[0] }},
	{kCmd, "Set / change recovery PUK", []fieldDef{{"New PUK", true}}, false, func(v []string) string { return "PUK " + v[0] }},
	{kCmd, "Auto-lock timeout", []fieldDef{{"Seconds (0 = off)", false}}, false, func(v []string) string { return "TIMEOUT " + v[0] }},
	{kind: kSep},
	{kDisk, "Disk (status / unlock / lock / pin / format)", nil, false, nil},
	{kind: kSep},
	{kProfiles, "Profiles (create / select / rename / erase)", nil, false, nil},
	{kCreds, "Credentials (list / delete)", nil, false, nil},
	{kind: kSep},
	{kCmd, "Backup to drive", []fieldDef{{"Backup password", true}}, false, func(v []string) string { return "BACKUP " + v[0] }},
	{kCmd, "Restore from drive", []fieldDef{{"Backup password", true}, {"New passphrase", true}, {"New PUK", true}}, false, func(v []string) string { return "RESTORE " + v[0] + " " + v[1] + " " + v[2] }},
	{kind: kSep},
	{kConsole, "Raw console", nil, false, nil},
	{kReset, "Reboot device (app mode)", nil, false, func([]string) string { return "RESET" }},
	{kReset, "Reboot to USB bootloader", nil, false, func([]string) string { return "RESET BOOTSEL" }},
	{kQuit, "Quit", nil, false, nil},
}

type model struct {
	width, height int

	device   *Device
	portPath string
	status   Status
	statusOK bool

	ports     []string
	portIdx   int
	manual    string

	screen  screen
	menuIdx int

	cur       act
	values    []string
	promptIdx int
	confirm   bool
	resetAfter bool

	output string
	err    error
	live   bool

	consoleInput string
	consoleLog   []string

	listKind     listKind
	listSel      int
	listProfiles []Profile
	listCreds    []Cred
	listConfirm  bool
	listCmd      string

	listInput       bool
	listInputTitle  string
	listInputFields []fieldDef
	listInputVals   []string
	listInputCur    int
	listInputAction func([]string) string
	inputScreen     screen

	diskStatus Status
	diskErr    error
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("215"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	selStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("24"))
)

// ---------------------------------------------------------------- Init

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), rescanCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func rescanCmd() tea.Cmd {
	return func() tea.Msg { p, _ := serial.GetPortsList(); return p }
}

// ---------------------------------------------------------------- commands

func (m model) fetchStatus() tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return nil
		}
		r, err := m.device.Exec("STATUS")
		if err != nil {
			return errMsg(err)
		}
		return statusMsg(ParseStatus(r))
	}
}

func (m model) execCommand(cmd string) tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		r, err := m.device.Exec(cmd)
		if err != nil {
			return errMsg(err)
		}
		return resultMsg(r)
	}
}

func (m model) consoleSend(line string) tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		r, err := m.device.Exec(line)
		if err != nil {
			return errMsg(err)
		}
		return consoleResultMsg(r)
	}
}

func (m model) resetDevice(cmd string) tea.Cmd {
	return func() tea.Msg {
		if m.device == nil {
			return errMsg(errors.New("not connected"))
		}
		_ = m.device.Reset(cmd)
		return resultMsg("device rebooted")
	}
}

func (m model) listCommand() string {
	if m.listKind == listProfiles {
		return "PROFILE LIST"
	}
	return "CREDS LIST"
}

func (m model) fetchProfiles() tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		r, err := m.device.Exec("PROFILE LIST")
		if err != nil {
			return errMsg(err)
		}
		return listProfilesMsg(ParseProfiles(r))
	}
}

func (m model) fetchCreds() tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		r, err := m.device.Exec("CREDS LIST")
		if err != nil {
			return errMsg(err)
		}
		return listCredsMsg(ParseCreds(r))
	}
}

// execAndRefresh runs a mutating command, then reloads the list and returns
// its parsed contents, so the list stays current in one serial transaction.
func (m model) execAndRefresh(command string, kind listKind) tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		if _, err := m.device.Exec(command); err != nil {
			return errMsg(err)
		}
		r, err := m.device.Exec(m.listCommand())
		if err != nil {
			return errMsg(err)
		}
		switch kind {
		case listProfiles:
			return listProfilesMsg(ParseProfiles(r))
		default:
			return listCredsMsg(ParseCreds(r))
		}
	}
}

// listLen returns the number of rows in the active list.
func (m model) listLen() int {
	if m.listKind == listProfiles {
		return len(m.listProfiles)
	}
	return len(m.listCreds)
}

func (m model) fetchDisk() tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		r, err := m.device.Exec("DISK STATUS")
		if err != nil {
			return errMsg(err)
		}
		return diskMsg(ParseStatus(r))
	}
}

// execAndRefreshDisk runs a disk command then reloads DISK STATUS, staying on
// the disk screen with the updated state in one serial transaction.
func (m model) execAndRefreshDisk(command string) tea.Cmd {
	return func() tea.Msg {
		if m.device == nil || !m.device.Connected() {
			return errMsg(errors.New("not connected"))
		}
		if _, err := m.device.Exec(command); err != nil {
			return errMsg(err)
		}
		r, err := m.device.Exec("DISK STATUS")
		if err != nil {
			return errMsg(err)
		}
		return diskMsg(ParseStatus(r))
	}
}

// ---------------------------------------------------------------- Update

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch m.screen {
		case scrConnect:
			return m.updateConnect(msg)
		case scrMain:
			return m.updateMain(msg)
		case scrPrompt:
			return m.updatePrompt(msg)
		case scrShow:
			return m.updateShow(msg)
		case scrConsole:
			return m.updateConsole(msg)
		case scrList:
			return m.updateList(msg)
		case scrDisk:
			return m.updateDisk(msg)
		}

	case tickMsg:
		var cmds []tea.Cmd
		if m.device != nil && m.device.Connected() && (m.screen == scrMain || (m.screen == scrShow && m.live)) {
			cmds = append(cmds, m.fetchStatus())
		}
		cmds = append(cmds, tickCmd())
		return m, tea.Batch(cmds...)

	case diskMsg:
		m.diskStatus = Status(msg)
		m.diskErr = nil
		return m, nil

	case listProfilesMsg:
		m.listProfiles = []Profile(msg)
		m.listSel = 0
		m.listConfirm = false
		return m, nil

	case listCredsMsg:
		m.listCreds = []Cred(msg)
		m.listSel = 0
		m.listConfirm = false
		return m, nil

	case []string:
		m.ports = msg
		if m.portIdx >= len(m.ports) {
			m.portIdx = 0
		}
		return m, nil

	case connMsg:
		m.device = msg
		m.statusOK = false
		m.screen = scrMain
		return m, m.fetchStatus()

	case statusMsg:
		m.status = Status(msg)
		m.statusOK = true
		m.live = true
		if m.screen == scrShow {
			m.renderStatus()
		}
		return m, nil

	case resultMsg:
		m.output = string(msg)
		m.err = nil
		if m.resetAfter {
			m.resetAfter = false
			m.device.Disconnect()
			m.device = nil
			m.statusOK = false
			m.screen = scrConnect
			return m, nil
		}
		m.screen = scrShow
		m.live = false
		return m, nil

	case consoleResultMsg:
		if m.screen == scrConsole {
			m.consoleLog = append(m.consoleLog, string(msg))
		}
		return m, nil

	case errMsg:
		m.err = msg
		if m.screen == scrConsole {
			m.consoleLog = append(m.consoleLog, errStyle.Render(msg.Error()))
			return m, nil
		}
		if m.screen == scrDisk {
			m.diskErr = msg
			m.diskStatus = Status{}
			return m, nil
		}
		m.screen = scrShow
		m.live = false
		return m, nil
	}
	return m, nil
}

// ---------------------------------------------------------------- connect

func (m model) updateConnect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		return m, tea.Quit
	case tea.KeyUp:
		if len(m.ports) > 0 && m.portIdx > 0 {
			m.portIdx--
		}
	case tea.KeyDown:
		if len(m.ports) > 0 && m.portIdx < len(m.ports)-1 {
			m.portIdx++
		}
	case tea.KeyBackspace:
		if len(m.ports) == 0 && len(m.manual) > 0 {
			m.manual = m.manual[:len(m.manual)-1]
		}
	case tea.KeyEnter:
		path := ""
		if len(m.ports) > 0 {
			path = m.ports[m.portIdx]
		} else if strings.TrimSpace(m.manual) != "" {
			path = strings.TrimSpace(m.manual)
		}
		if path == "" {
			return m, nil
		}
		return m, func() tea.Msg {
			dev, err := Connect(path, defaultBaud)
			if err != nil {
				return errMsg(err)
			}
			cm := connMsg(dev)
			return cm
		}
	case tea.KeyRunes:
		if len(m.ports) > 0 {
			for _, r := range msg.Runes {
				if r == 'r' || r == 'R' {
					return m, rescanCmd()
				}
				if r == 'q' || r == 'Q' {
					return m, tea.Quit
				}
			}
		} else {
			for _, r := range msg.Runes {
				if r == 8 || r == 127 {
					if len(m.manual) > 0 {
						m.manual = m.manual[:len(m.manual)-1]
					}
				} else {
					m.manual += string(r)
				}
			}
		}
	}
	return m, nil
}

// ---------------------------------------------------------------- main menu

func (m model) updateMain(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyUp:
		m.moveMenu(-1)
	case tea.KeyDown, tea.KeyTab:
		m.moveMenu(1)
	case tea.KeyEnter:
		return m.activate(m.menuIdx)
	}
	return m, nil
}

func (m *model) moveMenu(d int) {
	for i := 0; i < len(menu); i++ {
		m.menuIdx = (m.menuIdx + d + len(menu)) % len(menu)
		if menu[m.menuIdx].kind != kSep {
			return
		}
	}
}

func (m model) activate(idx int) (tea.Model, tea.Cmd) {
	a := menu[idx]
	switch a.kind {
	case kQuit:
		return m, tea.Quit
	case kSep:
		return m, nil
	}
	m.cur = a
	switch a.kind {
	case kStatus:
		m.live = true
		m.output = ""
		return m, m.fetchStatus()
	case kConsole:
		m.screen = scrConsole
		return m, nil
	case kProfiles:
		m.listKind = listProfiles
		m.listSel = 0
		m.listConfirm = false
		m.screen = scrList
		return m, m.fetchProfiles()
	case kCreds:
		m.listKind = listCreds
		m.listSel = 0
		m.listConfirm = false
		m.screen = scrList
		return m, m.fetchCreds()
	case kDisk:
		m.listConfirm = false
		m.listInput = false
		m.screen = scrDisk
		return m, m.fetchDisk()
	case kReset:
		m.confirm = true
		m.promptIdx = 0
		m.screen = scrPrompt
		return m, nil
	case kCmd:
		if len(a.fields) == 0 && !a.askYes {
			return m, m.execCommand(a.build(nil))
		}
		m.values = make([]string, len(a.fields))
		m.promptIdx = 0
		m.confirm = false
		m.screen = scrPrompt
		return m, nil
	}
	return m, nil
}

// ---------------------------------------------------------------- prompt

func (m model) updatePrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.screen = scrMain
		return m, nil
	case tea.KeyBackspace:
		if m.confirm {
			m.screen = scrMain
			return m, nil
		}
		if len(m.values[m.promptIdx]) > 0 {
			m.values[m.promptIdx] = m.values[m.promptIdx][:len(m.values[m.promptIdx])-1]
		}
	case tea.KeyEnter:
		if m.confirm {
			m.screen = scrMain
			return m, nil
		}
		if m.promptIdx < len(m.cur.fields)-1 {
			m.promptIdx++
		} else if m.cur.askYes {
			m.confirm = true
		} else {
			return m.submit(m.cur.build(m.values))
		}
	case tea.KeyRunes:
		if m.confirm {
			for _, r := range msg.Runes {
				if r == 'y' || r == 'Y' {
					return m.submit(m.cur.build(m.values))
				}
				m.screen = scrMain
				return m, nil
			}
		} else {
			for _, r := range msg.Runes {
				m.values[m.promptIdx] += string(r)
			}
		}
	}
	return m, nil
}

func (m model) submit(cmd string) (tea.Model, tea.Cmd) {
	if m.cur.kind == kReset {
		m.resetAfter = true
		return m, m.resetDevice(cmd)
	}
	return m, m.execCommand(cmd)
}

// ---------------------------------------------------------------- show / console

func (m model) updateShow(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc, tea.KeyEnter:
		m.screen = scrMain
		m.live = false
	case tea.KeyCtrlC:
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateConsole(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.screen = scrMain
		return m, nil
	case tea.KeyBackspace:
		if len(m.consoleInput) > 0 {
			m.consoleInput = m.consoleInput[:len(m.consoleInput)-1]
		}
	case tea.KeyEnter:
		line := strings.TrimSpace(m.consoleInput)
		m.consoleInput = ""
		if line == "" {
			return m, nil
		}
		m.consoleLog = append(m.consoleLog, "> "+line)
		return m, m.consoleSend(line)
	case tea.KeyRunes:
		for _, r := range msg.Runes {
			m.consoleInput += string(r)
		}
	}
	return m, nil
}

// updateList drives the navigable profiles/credentials list screens.
func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.listInput {
		return m.updateListInput(msg)
	}
	n := m.listLen()
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc, tea.KeyEnter:
		m.screen = scrMain
		return m, nil
	case tea.KeyUp:
		if m.listConfirm {
			m.listConfirm = false
		} else if m.listSel > 0 {
			m.listSel--
		}
	case tea.KeyDown, tea.KeyTab:
		if !m.listConfirm && n > 0 && m.listSel < n-1 {
			m.listSel++
		}
	case tea.KeyRunes:
		for _, r := range msg.Runes {
			if m.listConfirm {
				if r == 'y' || r == 'Y' {
					m.listConfirm = false
					return m, m.execAndRefresh(m.listCmd, m.listKind)
				}
				m.listConfirm = false
				continue
			}
			switch m.listKind {
			case listProfiles:
				switch r {
				case 'r', 'R', 'g', 'G':
					return m, m.fetchProfiles()
				case 's', 'S':
					if id, ok := m.selectedProfileID(); ok {
						return m, m.execAndRefresh("PROFILE SELECT "+id, listProfiles)
					}
				case 'e', 'E':
					if id, ok := m.selectedProfileID(); ok {
						m.startListInput("Rename profile "+id,
							[]fieldDef{{"New name", false}},
							func(v []string) string { return "PROFILE RENAME " + id + " " + v[0] })
					}
				case 'n', 'N':
					m.startListInput("Create profile",
						[]fieldDef{{"Profile id (0-7)", false}, {"Name", false}},
						func(v []string) string { return "PROFILE CREATE " + v[0] + " " + v[1] })
				case 'x', 'X', 'd', 'D':
					if id, ok := m.selectedProfileID(); ok {
						m.listConfirm = true
						m.listCmd = "PROFILE ERASE " + id
					}
				}
			case listCreds:
				switch r {
				case 'r', 'R', 'g', 'G':
					return m, m.fetchCreds()
				case 'd', 'D':
					if id, ok := m.selectedCredID(); ok {
						m.listConfirm = true
						m.listCmd = "CREDS DEL " + id + " yes"
					}
				}
			}
		}
	}
	return m, nil
}

// startListInput prepares and opens an inline field prompt inside a list screen.
func (m *model) startListInput(title string, fields []fieldDef, action func([]string) string) {
	m.startInput(title, fields, action, scrList)
}

func (m *model) startDiskInput(title string, fields []fieldDef, action func([]string) string) {
	m.startInput(title, fields, action, scrDisk)
}

func (m *model) startInput(title string, fields []fieldDef, action func([]string) string, target screen) {
	m.listInput = true
	m.listInputTitle = title
	m.listInputFields = fields
	m.listInputVals = make([]string, len(fields))
	m.listInputCur = 0
	m.listInputAction = action
	m.inputScreen = target
	m.listConfirm = false
}

// updateListInput handles typing while collecting fields for a list action.
func (m model) updateListInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.listInput = false
		return m, nil
	case tea.KeyBackspace:
		if len(m.listInputVals[m.listInputCur]) > 0 {
			m.listInputVals[m.listInputCur] = m.listInputVals[m.listInputCur][:len(m.listInputVals[m.listInputCur])-1]
		}
	case tea.KeyEnter:
		if m.listInputCur < len(m.listInputFields)-1 {
			m.listInputCur++
		} else {
			cmd := m.listInputAction(m.listInputVals)
			m.listInput = false
			if m.inputScreen == scrDisk {
				return m, m.execAndRefreshDisk(cmd)
			}
			return m, m.execAndRefresh(cmd, m.listKind)
		}
	case tea.KeyRunes:
		if m.listInputCur < len(m.listInputFields) {
			for _, r := range msg.Runes {
				m.listInputVals[m.listInputCur] += string(r)
			}
		}
	}
	return m, nil
}

// updateDisk drives the single consolidated disk screen.
func (m model) updateDisk(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.listInput {
		return m.updateListInput(msg)
	}
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc, tea.KeyEnter:
		m.screen = scrMain
		return m, nil
	case tea.KeyRunes:
		for _, r := range msg.Runes {
			if m.listConfirm {
				if r == 'y' || r == 'Y' {
					m.listConfirm = false
					return m, m.execAndRefreshDisk(m.listCmd)
				}
				m.listConfirm = false
				continue
			}
			switch r {
			case 'g', 'G', 'r', 'R':
				return m, m.fetchDisk()
			case 'u', 'U':
				m.startDiskInput("Unlock drive",
					[]fieldDef{{"Disk PIN", true}},
					func(v []string) string { return "DISK UNLOCK " + v[0] })
			case 'l', 'L':
				return m, m.execAndRefreshDisk("DISK LOCK")
			case 'f', 'F':
				m.listConfirm = true
				m.listCmd = "DISK LOCK FORCE YES"
			case 'p', 'P':
				m.startDiskInput("Set disk PIN",
					[]fieldDef{{"New disk PIN", true}},
					func(v []string) string { return "DISK SETPIN " + v[0] })
			case 'b', 'B':
				m.startDiskInput("Clear disk-PIN lock (PUK)",
					[]fieldDef{{"Recovery PUK", true}},
					func(v []string) string { return "DISK UNBLOCK " + v[0] })
			case 'x', 'X':
				m.listConfirm = true
				m.listCmd = "DISK FORMAT YES"
			}
		}
	}
	return m, nil
}

func (m model) selectedProfileID() (string, bool) {
	if m.listKind != listProfiles || m.listSel < 0 || m.listSel >= len(m.listProfiles) {
		return "", false
	}
	return itoaN(m.listProfiles[m.listSel].ID), true
}

func (m model) selectedCredID() (string, bool) {
	if m.listKind != listCreds || m.listSel < 0 || m.listSel >= len(m.listCreds) {
		return "", false
	}
	id := m.listCreds[m.listSel].ID
	return id, id != ""
}

// ---------------------------------------------------------------- helpers

func (m *model) renderStatus() {
	s := m.status
	var b strings.Builder
	if s.Version != "" {
		fmt.Fprintf(&b, "Firmware:     %s\n", s.Version)
	}
	fmt.Fprintf(&b, "Device state: %s\n", s.State)
	fmt.Fprintf(&b, "Drive:        %s\n", s.Disk)
	if s.FlushPending {
		b.WriteString("  (write flush pending — keep powered)\n")
	}
	fmt.Fprintf(&b, "Active profile: %s\n", itoaN(s.Profile))
	fmt.Fprintf(&b, "Timeout:        %ds\n", s.Timeout)
	fmt.Fprintf(&b, "Unlock pass fails: %d (blocked: %v)\n", s.PassFail, s.PassBlocked)
	fmt.Fprintf(&b, "CTAP2 PIN fails:   %d\n", s.PinFail)
	fmt.Fprintf(&b, "PUK fails:          %d\n", s.PUKFail)
	fmt.Fprintf(&b, "Disk PIN fails:     %d\n", s.DiskFail)
	m.output = b.String()
}

func itoaN(n int) string {
	if n < 0 {
		return "?"
	}
	return fmt.Sprintf("%d", n)
}

func (m model) connLine() string {
	if m.device != nil && m.device.Connected() {
		extra := ""
		if m.statusOK {
			extra = fmt.Sprintf(" · %s · drive %s · profile %s",
				m.status.State, m.status.Disk, itoaN(m.status.Profile))
		}
		return okStyle.Render("connected") + dimStyle.Render(m.portPath) + dimStyle.Render(extra)
	}
	return errStyle.Render("disconnected")
}

func headerBar(m model) string {
	title := titleStyle.Render(" Fjaeger TUI ")
	conn := m.connLine()
	return title + dimStyle.Render("  |  ") + conn
}
