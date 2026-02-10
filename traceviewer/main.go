package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/pkg/draw"
)

type model struct {
	mu *sync.Mutex

	lastBatchUpdate time.Time

	width  int
	height int

	tv *treeView

	foldStack []foldFn
	collapse  bool
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
		switch msg.Action {
		case tea.MouseAction(tea.MouseButtonWheelUp):
			if m.tv.cursor > 0 {
				m.tv.cursor--
				if m.tv.cursor < m.tv.start {
					m.tv.start--
					m.tv.end--
				}
			}
		case tea.MouseAction(tea.MouseButtonWheelDown):
			if m.tv.cursor < m.tv.root.size-1 {
				m.tv.cursor++
				if m.tv.cursor >= m.tv.end {
					m.tv.start++
					m.tv.end++
				}
			}
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "B":
			m.tv.cursor = 1
		case "s":
			if m.tv.selected != nil {
				m.tv.selected.sort()
			}
		case "up", "k":
			if m.tv.cursor > 0 {
				m.tv.cursor--
				if m.tv.cursor < m.tv.start {
					m.tv.start--
					m.tv.end--
				}
			}
		case "down", "j":
			if m.tv.cursor < m.tv.root.size-1 {
				m.tv.cursor++
				if m.tv.cursor >= m.tv.end {
					m.tv.start++
					m.tv.end++
				}
			}
		case "x":
			if m.tv.selected != nil {
				//m.tv.selected.collapsed = !m.tv.selected.collapsed
				m.tv.selected.setCollapsed(!m.tv.selected.collapsed)
			}
		}

	case tea.WindowSizeMsg:
		// Capture terminal dimensions when it resizes
		m.width = msg.Width
		m.height = msg.Height
		m.tv.end = msg.Height - 1
	case tickEvent:
	case pwruEventMsg:
		m.mu.Lock()
		for _, e := range msg.events {
			m.tv.upsert(&e, m.collapse, folderFn(&e, m.foldStack))
		}

		m.mu.Unlock()
	}

	return m, nil
}

// generate tuple string, normalize such that higher port is always the src
// such that bidirectional flows are grouped.
func tupleStr(t Tuple, normalize bool) string {
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
		return tupleStr(e.Tunnel, true)
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
		return e.Addr
	},
	"func": func(e Event) string {
		return e.Func
	},
}

// list of trees
type treeListView struct {
	root       *node // note: root is not drawn.
	count      int
	indexStack []IndexFn

	// draw window data
	windowStart int
	windowSize  int

	selected *node
	window   []walkedNode
	cursor   int
}

var update = 0

type pktView struct {
	tupleView
	event *Event

	skb string
}

type tupleView struct {
	saddr string
	sport uint16
	daddr string
	dport uint16
}

func eventToPktView(e *Event) *pktView {
	return &pktView{
		event: e,
		skb:   e.Func,
		tupleView: tupleView{
			saddr: e.Tuple.Saddr,
			sport: e.Tuple.Sport,
			daddr: e.Tuple.Daddr,
			dport: e.Tuple.Dport,
		},
	}
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

func renderPacketText(pv *pktView, w int) string {
	e := pv.event
	mark := fmt.Sprintf("0x%08x", e.Meta.Mark)

	saddr := e.Tuple.Saddr + ":" + strconv.Itoa(int(e.Tuple.Sport))
	daddr := e.Tuple.Daddr + ":" + strconv.Itoa(int(e.Tuple.Dport))

	txt := "\n"
	txt += draw.Header(w) + "\n"
	txt += draw.Line(w, " SOCKET BUFFER DATA (SKB):") + "\n"
	txt += draw.Break(w) + "\n"
	txt += draw.Line(w, " skb_addr:"+e.Addr) + "\n"
	txt += draw.Line(w, " mark:"+mark) + "\n"
	txt += draw.Line(w, " func_name:"+e.Func) + "\n"
	txt += draw.Line(w, " saddr:"+saddr) + "\n"
	txt += draw.Line(w, " daddr:"+daddr) + "\n"
	txt += draw.Line(w, " ifindex:"+strconv.Itoa(int(e.Meta.Ifindex))) + "\n"

	for range 10 {
		draw.Line(w, "")
	}

	// If we have a tunnel header then display that:
	if e.Tunnel.Sport != 0 && e.Tunnel.Dport != 0 {
		saddr = fmt.Sprintf("%s:%d", e.Tunnel.Saddr, e.Tunnel.Sport)
		daddr = fmt.Sprintf("%s:%d", e.Tunnel.Daddr, e.Tunnel.Dport)
		txt += draw.Line(w, " "+draw.Header(w-4)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "TUNNEL:")) + "\n"
		txt += draw.Line(w, " "+draw.Break(w-4)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "saddr:"+saddr)) + "\n"
		txt += draw.Line(w, " "+draw.Line(w-4, "daddr:"+daddr)) + "\n"
		txt += draw.Line(w, " "+draw.Footer(w-4)) + "\n"
	}

	txt += draw.Footer(w)
	return txt
}

func renderBranchStats(r, n *node, w int) string {
	txt := "\n"
	txt += draw.Header(w) + "\n"
	txt += draw.Line(w, " TRACES:") + "\n"
	txt += draw.Break(w) + "\n"
	txt += draw.Line(w, " trace_count:"+strconv.Itoa(n.realSize)) + "\n"
	txt += draw.Line(w, " total_count:"+strconv.Itoa(r.realSize)) + "\n"
	txt += draw.Footer(w)
	return txt
}

func (p *pktView) View(width int) string {
	b := &strings.Builder{}
	b.WriteString("SKB: ")
	b.WriteString(p.skb + "\n")
	b.WriteString("source_addr: " + p.tupleView.saddr + ":" + strconv.Itoa(int(p.tupleView.sport)) + "\n")
	b.WriteString("dest_addr: " + p.tupleView.daddr + ":" + strconv.Itoa(int(p.tupleView.dport)) + "\n")
	return renderPacketText(p, width)
}

type walkedNode struct {
	*node
	index int
	depth int
}

type Tuple struct {
	Saddr   string
	Daddr   string
	Sport   uint16
	Dport   uint16
	L3Proto uint16
	L4Proto uint8
}

type Event struct {
	Addr   string    `json:"skb"`
	Func   string    `json:"func"`
	Tuple  Tuple     `json:"tuple"`
	Tunnel Tuple     `json:"tunnel"`
	Meta   pwru.Meta `json:"meta"`
}

func parseIP(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

func (e Event) toPWRUEvent() *pwru.Event {
	skb, _ := strconv.ParseUint(strings.TrimPrefix(e.Addr, "0x"), 16, 64)
	return &pwru.Event{
		SkbAddr: skb,
		Tuple: pwru.Tuple{
			Saddr:   parseIP(e.Tuple.Saddr).As16(),
			Daddr:   parseIP(e.Tuple.Daddr).As16(),
			Sport:   e.Tuple.Sport,
			Dport:   e.Tuple.Dport,
			L3Proto: e.Tuple.L3Proto,
			L4Proto: e.Tuple.L4Proto,
		},
	}
}

func (m *model) View() string {
	leftStyle := lipgloss.NewStyle().
		Width(m.width / 2).
		Height(m.height)

	left := leftStyle.Render(m.tv.View())

	var right string
	if m.tv.selected != nil {
		rw := (m.width / 2) - 1
		if m.tv.selected.pkt != nil {
			right = m.tv.selected.pkt.View(rw)
		} else {
			right = renderBranchStats(m.tv.root, m.tv.selected, rw)
		}
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
			return fmt.Sprintf("trace: %s", e.Func), false
		}

		return fns[i](*e), i < len(fns)
	}
}

func main() {
	folds := flag.String("folds", "tuple.skb", "a string description for folds")
	collapse := flag.Bool("collapse", false, "will collapse folds by default")
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
	//fns = append(fns, foldFns["func"])

	tv := &treeView{
		cursor: 0,
		root: &node{
			size:       1,
			realSize:   1,
			strToChild: make(map[string]*node),
		},

		start: 0,
		end:   10,
	}

	m := &model{
		mu:        &sync.Mutex{},
		tv:        tv,
		foldStack: fns,
		collapse:  *collapse,
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

	done := make(chan struct{})

	go func() {
		defer close(done)

		batchSize := 1
		batch := make([]Event, 0, batchSize)
		forceUpsert := time.NewTicker(time.Second * 2)

		for {
			select {
			case <-forceUpsert.C:
				p.Send(pwruEventMsg{events: batch})
				batch = batch[:0]
			case line, ok := <-lines:
				if !ok {
					return // stdin finished
				}

				e := &Event{}
				if err := json.Unmarshal([]byte(line), e); err != nil {
					continue
				}

				batch = append(batch, *e)
				if len(batch) == 5 {
					p.Send(pwruEventMsg{events: batch})
					batch = batch[:0]
				}
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(time.Second * 10)
}

type node struct {
	collapsed bool
	realSize  int
	size      int
	cumSize   []int // always same size as children, cumSize[i] == sum(children[0...i].size)

	children   []*node
	strToChild map[string]*node
	parent     *node

	str string

	pkt *pktView
}

type traversalNode struct {
	depth int
	n     *node
}

// traversePreOrderRange returns nodes in pre-order traversal within the specified [start, end) index range.
func (n *node) traversePreOrderRange(start, end, current, depth int) []traversalNode {
	if current >= end || current+n.size <= start {
		return nil
	}

	var result []traversalNode
	if current >= start && current < end {
		result = append(result, traversalNode{
			depth: depth,
			n:     n,
		})
	}

	if n.collapsed {
		return result
	}

	// The children start at current + 1
	childStartOffset := current + 1

	// Find the first child that might contain 'start'
	// Search for i such that childStartOffset + cumSize[i] > start
	searchStart := start - childStartOffset
	idx := sort.Search(len(n.cumSize), func(i int) bool {
		return n.cumSize[i] > searchStart
	})

	for i := idx; i < len(n.cumSize); i++ {
		prevCumSize := 0
		if i > 0 {
			prevCumSize = n.cumSize[i-1]
		}

		childPos := childStartOffset + prevCumSize

		// If this child starts after the end of our range, we are done
		if childPos >= end {
			break
		}

		result = append(result, n.children[i].traversePreOrderRange(start, end, childPos, depth+1)...)
	}

	return result
}

func (n *node) isCollapsable() bool {
	return n.parent != nil
}

// setCollapsed updates the collapsed state of the node and recomputes sizes for it and its ancestors.
func (n *node) setCollapsed(collapsed bool) {
	if n == nil || !n.isCollapsable() || // cannot expand a leaf
		n.collapsed == collapsed { // no-op, avoid recomputing.
		return
	}

	n.collapsed = collapsed
	curr := n
	curr.size = 1
	curr.realSize = 1
	if n.collapsed {
		// If we have collapsed, this node is already done
		// so we start at the parent instead.
		curr = n.parent
		n.cumSize = []int{}
	} else {
		n.cumSize = make([]int, len(n.children))
	}

	// Fixup curr all curr nodes.
	for curr != nil {
		curr.size = 1
		if curr.collapsed {
			curr.cumSize = []int{}
		} else {
			// TODO: Only csum after our child node changes
			//	we can optimize by looking up child in index
			// 	and only fixing up csum thereafter.

			curr.cumSize = make([]int, len(curr.children))
			currentCumSize := 0
			for i, child := range curr.children {
				curr.size += child.size
				currentCumSize += child.size
				curr.cumSize[i] = currentCumSize
			}
		}

		curr = curr.parent
	}
}

func (n *node) sort() {
	if n.strToChild == nil {
		return
	}
	keys := slices.Collect(maps.Keys(n.strToChild))
	sort.Strings(keys)

	n.children = nil
	for _, k := range keys {
		n.children = append(n.children, n.strToChild[k])
	}
}

// upsert recursively inserts or updates a path in the tree based on the provided index function.
func (n *node) upsert(e *Event, collapse bool, index func(depth int) (string, bool), depth int) {
	key, ok := index(depth)

	if ok {
		if n.strToChild == nil {
			n.strToChild = make(map[string]*node)
		}
		child, exists := n.strToChild[key]
		if !exists {
			child = &node{str: key, size: 1, realSize: 1, parent: n, collapsed: collapse}
			n.children = append(n.children, child)
			n.strToChild[key] = child
		}
		child.upsert(e, collapse, index, depth+1)
	} else {
		leaf := &node{
			str: key, size: 1,
			parent: n,
			pkt:    eventToPktView(e),
		}
		n.children = append(n.children, leaf)
	}

	// Maintain size and cumSize up the tree
	n.size = 1
	n.realSize = 1
	if n.collapsed {
		n.cumSize = nil
		return
	}

	n.cumSize = make([]int, len(n.children))
	currentCumSize := 0
	for i, child := range n.children {
		n.size += child.size
		n.realSize += child.realSize
		currentCumSize += child.size
		n.cumSize[i] = currentCumSize
	}
}

type treeView struct {
	selected *node
	cursor   int
	start    int
	end      int

	root *node
}

// traversePreOrderRange returns nodes in pre-order traversal within the specified [start, end) index range.
func (tv *treeView) traversePreOrderRange(start, end int) []traversalNode {
	if tv.root == nil || start < 0 || start >= tv.root.size {
		return nil
	}
	if end <= start {
		return nil
	}
	return tv.root.traversePreOrderRange(start, end, 0, 0)
}

// upsert ensures the root exists and inserts or updates a path starting from the root.
func (tv *treeView) upsert(e *Event, collapse bool, index func(depth int) (string, bool)) {
	if tv.root == nil {
		tv.root = &node{str: "root", size: 1}
	}
	tv.root.upsert(e, collapse, index, 0)
}

func (t *treeView) View() string {
	b := &strings.Builder{}

	// We skip the root node when drawing.
	window := t.traversePreOrderRange(t.start+1, t.end+1)

	// Handle empty tree case
	if len(window) == 0 {
		b.WriteString("(empty tree)\n")
		return b.String()
	}

	// Calculate the cursor's position in the window (should be at index 10, or less if near start)
	cursorIndex := t.cursor - t.start

	// Draw each node in the window
	for i, tn := range window {
		// Indentation based on depth
		pre := strings.Repeat("  ", int(tn.depth))

		// Determine expander arrow
		expandIndicator := "  " // two spaces for leaf nodes (no children)
		if len(tn.n.children) > 0 {
			if tn.n.collapsed {
				expandIndicator = "▶ "
			} else {
				expandIndicator = "▼ "
			}
		}

		// Draw checkbox - "[x]" for selected (cursor), "[ ]" for unselected
		checkbox := "[ ]"
		if i == cursorIndex {
			checkbox = "[x]"
			t.selected = tn.n
		}

		b.WriteString(pre + expandIndicator + checkbox + " " + tn.n.str + "\n")
	}

	return b.String()
}
