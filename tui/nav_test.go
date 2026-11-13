package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestListNavigation(t *testing.T) {
	m := model{
		screen:       scrList,
		listKind:     listProfiles,
		listProfiles: []Profile{{ID: 0, Name: "a"}, {ID: 1, Name: "b"}, {ID: 2, Name: "c"}},
	}
	checks := []struct {
		key  tea.KeyType
		want int
	}{
		{tea.KeyDown, 1},
		{tea.KeyDown, 2},
		{tea.KeyDown, 2},
		{tea.KeyUp, 1},
		{tea.KeyUp, 0},
	}
	for _, c := range checks {
		m2, _ := m.updateList(tea.KeyMsg{Type: c.key})
		m = m2.(model)
		if m.listSel != c.want {
			t.Fatalf("key %v want sel=%d got=%d", c.key, c.want, m.listSel)
		}
	}
	// Esc returns to main
	m2, _ := m.updateList(tea.KeyMsg{Type: tea.KeyEsc})
	if m2.(model).screen != scrMain {
		t.Fatalf("Esc should return to main")
	}
}

func TestProfileActionsBuild(t *testing.T) {
	m := model{
		screen:       scrList,
		listKind:     listProfiles,
		listProfiles: []Profile{{ID: 3, Name: "x"}},
	}
	// 's' -> execAndRefresh PROFILE SELECT 3 (verify command string via execAndRefresh not needed; check sel helper)
	if id, ok := m.selectedProfileID(); !ok || id != "3" {
		t.Fatalf("selectedProfileID=%q,%v want 3,true", id, ok)
	}
	// 'x' arms erase confirmation
	m2, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if !m2.(model).listConfirm || m2.(model).listCmd != "PROFILE ERASE 3" {
		t.Fatalf("erase confirm not armed: %+v", m2.(model))
	}
	// 'y' confirms
	m3, _ := m2.(model).updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m3.(model).listConfirm {
		t.Fatal("confirm should clear after y")
	}
	// 'e' opens rename input
	m4, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	mm := m4.(model)
	if !mm.listInput || mm.listInputTitle != "Rename profile 3" {
		t.Fatalf("rename input not opened: %+v", mm)
	}
}

func TestListInputFlow(t *testing.T) {
	m := model{screen: scrList, listKind: listProfiles}
	m2, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	mm := m2.(model)
	if !mm.listInput || mm.listInputTitle != "Create profile" || len(mm.listInputFields) != 2 {
		t.Fatalf("create input not opened: %+v", mm)
	}
}

func TestFactoryResetNeedsConfirmation(t *testing.T) {
	idx := -1
	for i, a := range menu {
		if a.label == "FACTORY RESET (erase keys)" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("factory reset missing from menu")
	}
	m, cmd := (model{}).activate(idx)
	mm := m.(model)
	if cmd != nil || mm.screen != scrPrompt || !mm.confirm {
		t.Fatal("factory reset must prompt before sending")
	}
	m, cmd = mm.updatePrompt(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd != nil || m.(model).screen != scrMain {
		t.Fatal("cancellation must not send reset")
	}
	if menu[idx].build(nil) != "FACTORY RESET YES" {
		t.Fatal("incorrect reset command")
	}
}

func TestMenuKeepsSelectedItemVisible(t *testing.T) {
	m := model{height: 12, width: 80, menuIdx: len(menu) - 1}
	if !strings.Contains(m.viewMain(), "Quit") {
		t.Fatal("selected menu item is not visible")
	}
}
