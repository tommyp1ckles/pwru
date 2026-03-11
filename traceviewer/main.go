// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/pkg/draw"
	"github.com/cilium/pwru/pkg/models"
	"github.com/cilium/pwru/pkg/traceviewer/tree"
)

type model struct {
	mu *sync.Mutex

	traceCount int

	lastBatchUpdate time.Time

	width  int
	height int

	tv *tree.TreeView

	foldStack []foldFn
	collapse  bool

	enableMouseControls bool
}

func (m *model) Init() tea.Cmd {
	return nil
}

type pwruEventMsg struct {
	events []Event
}

type tickEvent struct{}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
			if msg.X < m.width/2 {
				m.tv.SetCursor(m.tv.GetStart() + msg.Y)
				m.tv.View()
				if m.tv.ColIsArrow(msg.X, msg.Y) {
					m.tv.ToggleCollapsedSelected()
				}
			}
		}
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m.tv.ActionUp()
		case tea.MouseButtonWheelDown:
			m.tv.ActionDown()
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "B":
			m.tv.SetCursor(1)
		case "s":
			m.tv.SortSelected()
		case "up", "k":
			m.tv.ActionUp()
		case "down", "j":
			m.tv.ActionDown()
		case "x":
			m.tv.ToggleCollapsedSelected()
		}

	case tea.WindowSizeMsg:
		// Capture terminal dimensions when it resizes
		m.width = msg.Width
		m.height = msg.Height
		m.tv.SetEnd(msg.Height - 1)
	case tickEvent:
	case pwruEventMsg:
		m.mu.Lock()
		for _, e := range msg.events {
			m.traceCount++
			m.tv.Upsert((*tree.Event)(&e), m.collapse, folderFn(&e, m.foldStack))
		}

		m.mu.Unlock()
	}

	return m, nil
}

// generate tuple string, normalize such that higher port is always the src
// such that bidirectional flows are grouped.
func tupleStr(t *models.Tuple, normalize bool) string {
	dport := t.Dport
	daddr := t.Daddr
	sport := t.Sport
	saddr := t.Saddr
	if normalize {
		if t.Dport > t.Sport {
			dport, sport = sport, dport
			daddr, saddr = saddr, daddr
		}
	}
	return fmt.Sprintf("%s:%d -> %s:%d", saddr, sport, daddr, dport)
}

var foldFns = map[string]func(Event) string{
	"tuple": func(e Event) string {
		return tupleStr(e.Tuple, true)
	},
	"tunnel": func(e Event) string {
		return tupleStr(e.TunnelTuple, true)
	},
	"daddr": func(e Event) string {
		return fmt.Sprintf("%s:%d", e.Tuple.Daddr, e.Tuple.Dport)
	},
	"saddr": func(e Event) string {
		return fmt.Sprintf("%s:%d", e.Tuple.Saddr, e.Tuple.Sport)
	},
	"sport": func(e Event) string {
		return fmt.Sprintf("%d", e.Tuple.Sport)
	},
	"dport": func(e Event) string {
		return fmt.Sprintf("%d", e.Tuple.Dport)
	},
	"skb": func(e Event) string {
		return e.Skb
	},
	"func": func(e Event) string {
		return e.Func
	},
}

var update = 0

type tupleView struct {
	saddr string
	sport uint16
	daddr string
	dport uint16
}

type IndexFn func(event *pwru.Event) string

func AddrToStr(proto uint16, addr [16]byte) string {
	return addrToStr(proto, addr)
}

func addrToStr(proto uint16, addr [16]byte) string {
	switch proto {
	case syscall.ETH_P_IP:
		return net.IP(addr[:4]).String()
	case syscall.ETH_P_IPV6:
		return fmt.Sprintf("[%s]", net.IP(addr[:]).String())
	default:
		return ""
	}
}

func renderPacketText(e *tree.Event, w int) string {
	mark := fmt.Sprintf("0x%08x", e.Mark)

	saddr := e.Tuple.Saddr + ":" + strconv.Itoa(int(e.Tuple.Sport))
	daddr := e.Tuple.Daddr + ":" + strconv.Itoa(int(e.Tuple.Dport))

	txt := "\n"
	txt += draw.Header(w) + "\n"
	txt += draw.Line(w, " SOCKET BUFFER DATA (SKB):") + "\n"
	txt += draw.Break(w) + "\n"
	txt += draw.Line(w, " skb_addr: "+e.Skb) + "\n"
	txt += draw.Line(w, " mark: "+mark) + "\n"
	txt += draw.Line(w, " func_name: "+e.Func) + "\n"
	if e.CallerFunc != "" {
		txt += draw.Line(w, " caller: "+e.CallerFunc) + "\n"
	}
	txt += draw.Line(w, " proto: "+strconv.Itoa(int(e.Proto))) + "\n"
	txt += draw.Line(w, " saddr: "+saddr) + "\n"
	txt += draw.Line(w, " daddr: "+daddr) + "\n"
	txt += draw.Line(w, " cb: "+fmt.Sprintf("%v", e.CB)) + "\n"
	txt += draw.Line(w, " netns: "+strconv.Itoa(int(e.Netns))) + "\n"
	txt += draw.Line(w, " iface: "+e.Iface) + "\n"
	txt += draw.Line(w, " len: "+strconv.Itoa(int(e.Len))) + "\n"
	txt += draw.Line(w, " process: "+e.Process) + "\n"

	// If we have a tunnel header then display that:
	if e.TunnelTuple.Sport != 0 && e.TunnelTuple.Dport != 0 {
		saddr = fmt.Sprintf("%s:%d", e.TunnelTuple.Saddr, e.TunnelTuple.Sport)
		daddr = fmt.Sprintf("%s:%d", e.TunnelTuple.Daddr, e.TunnelTuple.Dport)
		txt += draw.Line(w, " "+draw.Header(w-4)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "TUNNEL:")) + "\n"
		txt += draw.Line(w, " "+draw.Break(w-4)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "proto: "+strconv.Itoa(int(e.TunnelTuple.Proto)))) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "saddr: "+saddr)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "daddr: "+daddr)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "flags: "+e.TunnelTuple.Flags)) + "\n"
		txt += draw.Line(w, " "+draw.Footer(w-4)) + "\n"
	}

	txt += draw.Footer(w)
	return txt
}

// func (m *model) renderBranchStats(r, n *node, w int) string {
func (m *model) renderBranchStats(leafSize, w int) string {
	txt := "\n"
	txt += draw.Header(w) + "\n"
	txt += draw.Line(w, " TRACES:") + "\n"
	txt += draw.Break(w) + "\n"
	txt += draw.Line(w, " trace_count:"+strconv.Itoa(leafSize)) + "\n"
	txt += draw.Line(w, " total_count:"+strconv.Itoa(m.traceCount)) + "\n"
	txt += draw.Footer(w)
	return txt
}

type Event models.Event

func (m *model) View() string {
	leftStyle := lipgloss.NewStyle().
		Width(m.width / 2).
		Height(m.height)

	left := leftStyle.Render(m.tv.View())

	var right string
	selected := m.tv.GetSelected()
	rw := (m.width / 2) - 1
	if selected != nil {
		right = renderPacketText(selected.Event, rw)
	} else {
		right = m.renderBranchStats(m.tv.GetSelectedLeafSize(), rw)
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

type foldFn func(Event) string

func folderFn(e *Event, fns []foldFn) func(int) (string, bool) {
	return func(i int) (string, bool) {
		if i > len(fns) {
			return "", false
		}

		if i == len(fns) {
			if e.Time != nil {
				return fmt.Sprintf("%s event: %s", e.Func, e.Time.String()), false
			} else {
				return fmt.Sprintf("event: %s", e.Func), false
			}
		}

		return fns[i](*e), i < len(fns)
	}
}

func main() {
	folds := flag.String("folds", "tuple.skb", "a string description for folds")
	collapse := flag.Bool("collapse", false, "will collapse folds by default")
	enableMouse := flag.Bool("mouse", false, "enables using mouse input")
	flag.Parse()

	fns := []foldFn{}
	for _, tok := range strings.Split(*folds, ".") {
		fn, ok := foldFns[tok]
		if !ok {
			fmt.Fprintln(os.Stderr, "not a fold fn:", tok)
			os.Exit(1)
		}
		fns = append(fns, fn)
	}

	tv := tree.NewTreeView()

	m := &model{
		mu:                  &sync.Mutex{},
		tv:                  tv,
		foldStack:           fns,
		collapse:            *collapse,
		enableMouseControls: *enableMouse,
	}

	p := tea.NewProgram(
		m,
		tea.WithFPS(30),
		tea.WithAltScreen(),       // Use alternate screen buffer
		tea.WithMouseCellMotion(), // Enable mouse support (optional)
	)

	go func() {
		ticker := time.NewTicker(time.Millisecond * 500)
		for {
			<-ticker.C
			p.Send(tickEvent{})
		}
	}()

	lines := make(chan string, 256) // buffer helps decouple stdin from processing
	errCh := make(chan error, 1)

	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		errCh <- scanner.Err()
	}()

	go func() {
		batchSize := 1
		batch := make([]Event, 0, batchSize)
		forceUpsert := time.NewTicker(time.Second * 1)
		// Force a update very quickly for cases where initial input
		// is less than the batch size but waiting for the first forced
		// update makes it feel sluggish.
		firstUpdate := time.NewTimer(time.Millisecond * 10)

		maybeSendBatch := func(thresh int) {
			if len(batch) > thresh {
				p.Send(pwruEventMsg{events: batch})
				batch = make([]Event, 0, batchSize)
			}
		}
		for {
			select {
			case <-firstUpdate.C:
				firstUpdate.Stop()
				maybeSendBatch(0)
			case <-forceUpsert.C:
				maybeSendBatch(0)
			case line, ok := <-lines:
				if !ok {
					continue
				}

				e := &Event{}
				if err := json.Unmarshal([]byte(line), e); err != nil {
					continue
				}

				batch = append(batch, *e)
				maybeSendBatch(5)
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(time.Second * 10)
}
