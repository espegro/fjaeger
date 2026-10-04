package main

import (
	"bytes"
	"fmt"
	"strings"
)

const versionNote = "Fjaeger terminal controller"

func (m model) View() string {
	switch m.screen {
	case scrConnect:
		return m.viewConnect()
	case scrMain:
		return m.viewMain()
	case scrPrompt:
		return m.viewPrompt()
	case scrShow:
		return m.viewShow()
	case scrConsole:
		return m.viewConsole()
	case scrList:
		return m.viewList()
	case scrDisk:
		return m.viewDisk()
	}
	return ""
}

func (m model) pad() string      { return " " }
func tip(s string) string        { return dimStyle.Render(s) }

func (m model) viewConnect() string {
	var body strings.Builder
	body.WriteString("Pick a serial port.\n\n")
	if len(m.ports) > 0 {
		start := 0
		if m.portIdx > m.height-8 {
			start = m.portIdx - (m.height - 8)
		}
		for i := start; i < len(m.ports) && i < start+(m.height-7); i++ {
			line := m.ports[i]
			if i == m.portIdx {
				body.WriteString("  " + selStyle.Render("▸ "+line) + "\n")
			} else {
				body.WriteString("    " + line + "\n")
			}
		}
		body.WriteString("\n" + tip("↑/↓ select · Enter connect · r rescan · q quit"))
	} else {
		body.WriteString("No serial ports found — type a device path to open:\n\n")
		body.WriteString("  " + selStyle.Render("▸ "+m.manual+"▌") + "\n\n")
		body.WriteString(tip("type the path, e.g. /dev/ttyACM0 · Enter connect · Esc quit"))
	}
	return headerBar(m) + "\n\n" + body.String()
}

func (m model) viewMain() string {
	var body strings.Builder
	body.WriteString("Commands\n")
	body.WriteString(strings.Repeat("─", m.widthAtLeast(40)) + "\n")

	// Center the menu if there's room.
	for i, a := range menu {
		line := ""
		if a.kind == kSep {
			line = " " + dimStyle.Render(strings.Repeat("·", 6))
		} else {
			mark := "  "
			if i == m.menuIdx {
				mark = "▸ "
			}
			txt := a.label
			if m.connectedAs() {
				txt = mark + txt
			} else {
				txt = mark + txt
			}
			if i == m.menuIdx {
				line = "  " + selStyle.Render(mark+txt)
			} else {
				line = "  " + mark + txt
			}
		}
		body.WriteString(line + "\n")
	}
	body.WriteString("\n" + tip("↑/↓ move · Enter select · q quit"))
	return headerBar(m) + "\n\n" + body.String()
}

func (m model) viewPrompt() string {
	a := m.cur
	var b strings.Builder
	b.WriteString(titleStyle.Render(a.label))
	b.WriteString("\n\n")
	if m.confirm {
		b.WriteString("  " + errStyle.Render("Confirm? ") + selStyle.Render("(y/N)") + "\n\n")
		b.WriteString(tip("y to proceed, any other key to cancel"))
		b.WriteString("\n\n  Summary: " + dimStyle.Render(a.build(m.values)))
	} else {
		for i, f := range a.fields {
			prefix := "  "
			if i == m.promptIdx {
				prefix = "▸ "
			}
			val := m.values[i]
			if f.secret {
				val = strings.Repeat("•", len(val))
			}
			label := f.prompt
			b.WriteString(fmt.Sprintf("%s %s: %s%s\n", prefix, label, val, func() string {
				if i == m.promptIdx {
					return "▌"
				}
				return ""
			}()))
		}
		b.WriteString("\n" + tip("type to enter · Enter next/submit · Esc cancel"))
	}
	return headerBar(m) + "\n\n" + b.String()
}

func (m model) viewShow() string {
	var b strings.Builder
	if m.err != nil {
		b.WriteString(errStyle.Render("Error: " + m.err.Error()) + "\n\n")
	} else {
		b.WriteString(m.truncateOutput())
	}
	b.WriteString("\n" + tip("Enter/Esc to return"))
	return headerBar(m) + "\n\n" + b.String()
}

func (m model) viewConsole() string {
	avail := m.height
	if avail < 10 {
		avail = 10
	}
	log := m.consoleLog
	var lines []string
	// take the last (avail-4) log lines
	keep := avail - 4
	if len(log) > keep {
		lines = log[len(log)-keep:]
	} else {
		lines = log
	}
	var b strings.Builder
	b.WriteString(strings.Repeat("─", m.widthAtLeast(40)) + "\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString(strings.Repeat("─", m.widthAtLeast(40)) + "\n")
	b.WriteString("> " + m.consoleInput + "▌\n")
	b.WriteString(tip("type a raw command (e.g. HELP) · Enter send · Esc back"))
	return headerBar(m) + "\n\n" + b.String()
}

func (m model) connectedAs() bool { return m.device != nil && m.device.Connected() }

func (m model) widthAtLeast(n int) int {
	if m.width > n {
		return m.width - 4
	}
	return n
}

// truncateOutput keeps the output readable within the window.
func (m model) truncateOutput() string {
	out := m.output
	if out == "" {
		return dimStyle.Render("(no output)")
	}
	max := m.height - 6
	if max < 5 {
		max = 5
	}
	lines := strings.Split(out, "\n")
	if len(lines) <= max {
		return out
	}
	var b bytes.Buffer
	for _, l := range lines[:max] {
		b.WriteString(l + "\n")
	}
	b.WriteString(dimStyle.Render(fmt.Sprintf("… %d more lines", len(lines)-max)) + "\n")
	return b.String()
}

func (m model) viewList() string {
	var b strings.Builder

	if m.listInput {
		m.renderInput(&b)
		return headerBar(m) + "\n\n" + b.String()
	}

	if m.listKind == listProfiles {
		b.WriteString(titleStyle.Render("Profiles") + "  " + dimStyle.Render(fmt.Sprintf("%d found", len(m.listProfiles))) + "\n\n")
		m.renderTable(&b, []string{"ID", "Name", "Credentials", "Active"}, m.profileRows())
	} else {
		b.WriteString(titleStyle.Render("Credentials") + "  " + dimStyle.Render(fmt.Sprintf("%d found", len(m.listCreds))) + "\n\n")
		m.renderTable(&b, []string{"#", "Type", "Application", "Resident", "Fingerprint / ID"}, m.credRows())
	}
	if m.listConfirm {
		b.WriteString("\n  " + errStyle.Render("Confirm? ") + selStyle.Render("(y/N)") + "  " + dimStyle.Render(m.listCmd) + "\n")
	}
	help := "↑/↓ move · Enter/Esc back"
	switch m.listKind {
	case listProfiles:
		help += " · s select · e rename · n create · x erase · g refresh"
	case listCreds:
		help += " · d delete · g refresh"
	}
	b.WriteString("\n" + tip(help))
	return headerBar(m) + "\n\n" + b.String()
}

// renderTable renders aligned columns with the selected row highlighted and
// scrolled into view.
func (m model) renderTable(b *strings.Builder, header []string, rows [][]string) {
	cols := len(header)
	if len(rows) > 0 {
		cols = len(rows[0])
	}
	if cols == 0 {
		return
	}
	widths := make([]int, cols)
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i := 0; i < cols && i < len(r); i++ {
			if len(r[i]) > widths[i] {
				widths[i] = len(r[i])
			}
		}
	}
	for i, h := range header {
		b.WriteString(" " + bold(h, widths[i]))
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", sum(widths)+cols)) + "\n")

	// Determine the visible window so the selection stays on screen.
	avail := m.height - 6
	if avail < 3 {
		avail = 3
	}
	start := 0
	if len(rows) > avail {
		if m.listSel >= start+avail {
			start = m.listSel - avail + 1
		}
		if m.listSel < start {
			start = m.listSel
		}
	}
	for row := start; row < len(rows) && row < start+avail; row++ {
		line := " " + alignRow(rows[row], widths)
		if row == m.listSel {
			b.WriteString(selStyle.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	if len(rows) == 0 {
		b.WriteString(dimStyle.Render(" (none)") + "\n")
	}
}

func (m model) profileRows() [][]string {
	out := make([][]string, 0, len(m.listProfiles))
	for _, p := range m.listProfiles {
		active := ""
		if p.Active {
			active = "active"
		}
		nm := p.Name
		if nm == "" {
			nm = "(unnamed)"
		}
		out = append(out, []string{itoaN(p.ID), nm, itoaN(p.Count), active})
	}
	return out
}

func (m model) credRows() [][]string {
	out := make([][]string, 0, len(m.listCreds))
	for i, c := range m.listCreds {
		fp := c.Fingerprint
		if fp == "" {
			fp = "id:" + c.ID
		}
		out = append(out, []string{itoaN(i + 1), c.Type, c.Application, yesno(c.Resident), fp})
	}
	return out
}

func bold(s string, w int) string {
	return accS(s, w)
}

func accS(s string, w int) string {
	return fmt.Sprintf("%-*s", w, s)
}

func alignRow(cells []string, widths []int) string {
	parts := make([]string, len(cells))
	for i := 0; i < len(cells); i++ {
		parts[i] = fmt.Sprintf("%-*s", widths[i], cells[i])
	}
	return strings.Join(parts, " ")
}

func sum(a []int) int {
	t := 0
	for _, v := range a {
		t += v
	}
	return t
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (m model) viewDisk() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Drive") + "\n\n")

	if m.listInput {
		m.renderInput(&b)
		return headerBar(m) + "\n\n" + b.String()
	}

	ds := m.diskStatus
	if m.diskErr != nil {
		b.WriteString(errStyle.Render("Error: " + m.diskErr.Error()) + "\n\n")
	}
	if m.diskStatus.Disk == "" && m.diskErr == nil {
		b.WriteString(dimStyle.Render("(no status yet — press g to refresh)") + "\n\n")
	} else if ds.Disk != "" {
		b.WriteString("  State:        " + ds.Disk + "\n")
		b.WriteString("  Disk PIN fails: " + itoaN(ds.DiskFail) + "\n")
		if ds.FlushPending {
			b.WriteString("  (write flush pending — keep powered)\n")
		}
		b.WriteString("\n")
	}
	if m.listConfirm {
		b.WriteString("  " + errStyle.Render("Confirm? ") + selStyle.Render("(y/N)") + "  " + dimStyle.Render(m.listCmd) + "\n\n")
	}
	b.WriteString(tip("g refresh · u unlock · l lock · f force · p set pin · b unblock(PUK) · x format · Esc back"))
	return headerBar(m) + "\n\n" + b.String()
}

// renderInput draws the inline field prompt shared by list and disk screens.
func (m model) renderInput(b *strings.Builder) {
	b.WriteString(titleStyle.Render(m.listInputTitle) + "\n\n")
	for i, f := range m.listInputFields {
		mark := "  "
		if i == m.listInputCur {
			mark = "▸ "
		}
		val := m.listInputVals[i]
		if f.secret {
			val = strings.Repeat("•", len(val))
		}
		cursor := ""
		if i == m.listInputCur {
			cursor = "▌"
		}
		b.WriteString(fmt.Sprintf("%s %s: %s%s\n", mark, f.prompt, val, cursor))
	}
	b.WriteString("\n" + tip("Enter next / submit · Esc cancel"))
}
