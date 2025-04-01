package tui

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/cilium/pwru/internal/byteorder"
	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/tui/draw"
	"github.com/fatih/color"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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

var lastEvent *pwru.Event

func App(addr2Name pwru.Addr2Name) (*tview.Application, *tview.TreeNode) {
	app := tview.NewApplication()
	tree := tview.NewTreeView()

	// Create the root node
	root := tview.NewTreeNode("traces").
		SetColor(tcell.ColorBlue)

	// Set the root node in the tree
	tree.SetRoot(root).
		SetCurrentNode(root)

	pktView := tview.NewTextView().SetText("")
	// Enable selection and set a selection handler
	tree.SetChangedFunc(func(node *tview.TreeNode) {
		if node == nil {
			return
		}
		if node.GetText() == "traces" {
			return
		}
		// TODO: On the non leaf now, lets do a view thats like:
		// (cilium_vxlan) eth1(10 fn-calls)Mark:(In: 0xffff, Out: 0x1234)
		// (cilium_host) eth2(10 fn-calls)Mark:(In: 0xffff, Out: 0x1234)
		// eth0(10 fn-calls)Mark:(In: 0xffff, Out: 0x1234)
		if len(node.GetChildren()) == 0 {
			e, ok := node.GetReference().(*pwru.Event)
			if !ok {
				return
			}
			skbAddr := fmt.Sprintf("0x%016x", e.SkbAddr)
			mark := fmt.Sprintf("0x%08x", e.Meta.Mark)
			masks := decodeMark(uint16(e.Meta.Mark))
			if lastEvent == nil || lastEvent.Meta.Mark != e.Meta.Mark {
				mark = color.HiGreenString(mark)
			}
			ifindex := fmt.Sprintf("%d", e.Meta.Ifindex)
			fn := addr2Name.Addr2NameMap[e.Addr].Name()

			portStr := func(n uint16) string {
				return strconv.Itoa(int(byteorder.NetworkToHost16(n)))
			}
			saddr := addrToStr(e.Tuple.L3Proto, e.Tuple.Saddr) + ":" + portStr(e.Tuple.Sport)
			daddr := addrToStr(e.Tuple.L3Proto, e.Tuple.Daddr) + ":" + portStr(e.Tuple.Dport)

			w := 70
			txt := draw.Header(w) + "\n"
			txt += draw.Line(w, " SKB:") + "\n"
			txt += draw.Break(w) + "\n"
			txt += draw.Line(w, " skb_addr:"+skbAddr) + "\n"
			txt += draw.Line(w, " mark:"+mark) + "\n"
			for _, mask := range masks {
				txt += draw.Line(w, " *"+mask) + "\n"
			}
			txt += draw.Line(w, " ifindex:"+ifindex) + "\n"
			txt += draw.Line(w, " func_name:"+fn) + "\n"
			txt += draw.Line(w, " saddr:"+saddr) + "\n"
			txt += draw.Line(w, " daddr:"+daddr) + "\n"

			saddr = addrToStr(e.TunnelTuple.L3Proto, e.TunnelTuple.Saddr) + ":" + portStr(e.TunnelTuple.Sport)
			daddr = addrToStr(e.TunnelTuple.L3Proto, e.TunnelTuple.Daddr) + ":" + portStr(e.TunnelTuple.Dport)
			txt += draw.Line(w, " "+draw.Header(w-4)) + "\n"

			mark = fmt.Sprintf("0x%08x", e.Meta.Mark)
			masks = decodeMark(uint16(e.Meta.Mark))
			if lastEvent == nil || lastEvent.Meta.Mark != e.Meta.Mark {
				mark = color.HiGreenString(mark)
			}

			txt += draw.Line(w, " "+draw.Line(w-4, "TUNNEL:")) + "\n"
			txt += draw.Line(w, " "+draw.Break(w-4)) + "\n"
			txt += draw.Line(w, " "+draw.Line(w-4, "saddr: "+saddr)) + "\n"
			txt += draw.Line(w, " "+draw.Line(w-4, "daddr: "+daddr)) + "\n"
			txt += draw.Line(w, " "+draw.Line(w-4, "mark: "+mark)) + "\n"
			for _, mask := range masks {
				txt += draw.Line(w, " "+draw.Line(w-4, " * "+mask)) + "\n"
			}
			txt += draw.Line(w, " "+draw.Footer(w-4)) + "\n"

			txt += draw.Footer(w)

			pktView.SetText(txt)
			lastEvent = e
		}
	})
	tree.SetSelectedFunc(func(node *tview.TreeNode) {
		if node == nil {
			return
		}
		if node.GetText() == "traces" {
			return
		}
		if len(node.GetChildren()) > 0 {
			node.SetExpanded(!node.IsExpanded()) // Toggle expansion
		}

	})

	// 2,3
	flex := tview.NewFlex().
		AddItem(tree, 100, 2, true).
		AddItem(pktView, 0, 3, false)

	return app.SetRoot(flex, true).SetFocus(flex), root
}

var (
	MARK_MAGIC_HOST_MASK     uint16 = 0x0F00
	MARK_MAGIC_PROXY_INGRESS uint16 = 0x0A00
	MARK_MAGIC_PROXY_EGRESS  uint16 = 0x0B00
	MARK_MAGIC_HOST          uint16 = 0x0C00
	MARK_MAGIC_DECRYPT       uint16 = 0x0D00
	MARK_MAGIC_ENCRYPT       uint16 = 0x0E00
	MARK_MAGIC_IDENTITY      uint16 = 0x0F00
	MARK_MAGIC_TO_PROXY      uint16 = 0x0200
)

func decodeMark(m uint16) []string {
	pre := "(Cilium) MARK_MAGIC"
	hasMark := func(mark uint16) bool {
		return mark&MARK_MAGIC_HOST_MASK&m == mark
	}
	marks := []string{}
	if hasMark(MARK_MAGIC_PROXY_INGRESS) {
		marks = append(marks, pre+"_PROXY_INGRESS")
	}
	if hasMark(MARK_MAGIC_PROXY_EGRESS) {
		marks = append(marks, pre+"_PROXY_EGRESS")
	}
	if hasMark(MARK_MAGIC_HOST) {
		marks = append(marks, pre+"_MAGIC_HOST")
	}
	if hasMark(uint16(MARK_MAGIC_DECRYPT)) {
		marks = append(marks, pre+"_MAGIC_DECRYPT")
	}
	if hasMark(uint16(MARK_MAGIC_ENCRYPT)) {
		marks = append(marks, pre+"_MAGIC_ENCRYPT")
	}
	if hasMark(uint16(MARK_MAGIC_IDENTITY)) {
		marks = append(marks, pre+"_MAGIC_IDENTITY")
	}
	if hasMark(uint16(MARK_MAGIC_TO_PROXY)) {
		marks = append(marks, pre+"_MAGIC_TO_PROXY")
	}
	return marks
}

type traceTree struct {
	root *tview.TreeNode
}

func revTuple(tpl pwru.Tuple) pwru.Tuple {
	out := tpl
	copy(out.Daddr[:], tpl.Saddr[:])
	copy(out.Saddr[:], tpl.Daddr[:])
	out.Sport = tpl.Dport
	out.Dport = tpl.Sport
	return out
}

// Grouping, function(e) -> hash
//
// * TunnelTuple
//   - SKB Addr
//
// So it's a list of functions:
//
// [groupByTunnel, groupByMark, ...]

type GroupFn func(e *pwru.Event) string

// Ok, more efficient, this is a common prefix tree:
//
// tunnel-id.foo-id.mark
//
//
// --group-by="tunnel.mark"

func InsertGroup(root *tview.TreeNode, e *pwru.Event, addr2Name pwru.Addr2Name, groupFns []GroupFn) {
	insertGroup(root, e, addr2Name, append(groupFns, func(e *pwru.Event) string {
		return "[trace] " + addr2Name.Addr2NameMap[e.Addr].Name()
	}))
}

func insertGroup(curr *tview.TreeNode, e *pwru.Event, addr2Name pwru.Addr2Name, groupFns []GroupFn) {
	if len(groupFns) == 0 {
		return
	}

	gfn := groupFns[0]
	id := gfn(e)
	if len(groupFns) == 1 {
		// child fn -> always add without grouping.
		leaf := tview.NewTreeNode(id)
		leaf.SetColor(tcell.ColorPink)
		// leaf.SetReference(id)
		leaf.SetReference(e)
		leaf.SetExpanded(false)
		curr.AddChild(leaf)
		return
	} else {
		groupFns = groupFns[1:len(groupFns)]
	}

	var target *tview.TreeNode

	for _, grpNode := range curr.GetChildren() {
		obj := grpNode.GetReference()
		if obj == nil {
			continue
		}
		gn, ok := obj.(string)
		if !ok {
			continue
		}

		if gn == id {
			target = grpNode
			break
		}
	}
	if target == nil {
		target = tview.NewTreeNode(id)
		target.SetColor(tcell.ColorGreen)
		target.SetReference(id)
		target.SetExpanded(false)
		curr.AddChild(target)
	}

	insertGroup(target, e, addr2Name, groupFns)
}

var groupFnLookup = map[string]GroupFn{
	"tunnel-ip-version": groupByIPversion(true),
	"ip-version":        groupByIPversion(false),
	"tuple":             GroupByTupleConnection(false),
	"tunnel-tuple":      GroupByTupleConnection(true),
	"mark": func(e *pwru.Event) string {
		return fmt.Sprintf("0x%08x", e.Meta.Mark)
	},
}

func ParseGroupingString(fnNames []string) ([]GroupFn, error) {
	out := []GroupFn{}
	for _, fname := range fnNames {
		fn, ok := groupFnLookup[fname]
		if !ok {
			return nil, fmt.Errorf("no such fn %s", fname)
		}
		out = append(out, func(e *pwru.Event) string {
			return fmt.Sprintf("[%s] %s", fname, fn(e))
		})
	}
	return out, nil
}

func groupByIPversion(tunnel bool) GroupFn {
	return func(e *pwru.Event) string {
		tuple := e.Tuple
		if tunnel {
			tuple = e.TunnelTuple
		}
		switch tuple.L3Proto {
		case syscall.ETH_P_IP:
			return "ipv4"
		case syscall.ETH_P_IPV6:
			return "ipv6"
		default:
			return "unknown"
		}
	}
}

func GroupByTupleConnection(tunnel bool) GroupFn {
	return func(e *pwru.Event) string {
		tuple := e.Tuple
		if tunnel {
			tuple = e.TunnelTuple
		}

		if tuple.Sport < tuple.Dport {
			tuple = revTuple(tuple)
		}

		return pwru.GetTuple(tuple, false)
	}
}

// Proposal: Fold operation, for a node holding a event ptr, we can fold that by any thing in there
// For example. Event{}.FoldBySource(1234), FoldByTimeChunk(5*time.Minute).
func Insert(root *tview.TreeNode, e *pwru.Event, addr2Name pwru.Addr2Name, groupByTunnel bool) {
	tuple := func(ev *pwru.Event) pwru.Tuple {
		if groupByTunnel {
			return ev.TunnelTuple
		}
		return ev.Tuple
	}

	tuplePairs := root.GetChildren()
	var pairRef *pwru.Event
	// Pair node folds on 4-tuple (todo: make this for both directions).
	var pairNode *tview.TreeNode
	dir := "[→] "
	for _, tpn := range tuplePairs {
		obj := tpn.GetReference()
		if obj == nil {
			continue
		}
		// TODO: just store 4-tuple
		tp, ok := obj.(*pwru.Event)
		if !ok {
			continue
		}

		equals := func(a, b pwru.Tuple) bool {
			return bytes.Compare(a.Saddr[:4], b.Saddr[:4]) == 0 &&
				bytes.Compare(a.Daddr[:4], b.Daddr[:4]) == 0 &&
				a.Sport == b.Sport && a.Dport == b.Dport
		}
		eq := equals(tuple(tp), tuple(e))
		revEq := equals(revTuple(tuple(tp)), tuple(e))
		if revEq {
			dir = "[←] "
		}
		if eq || revEq {
			pairRef = tp
			pairNode = tpn
			break
		}
	}
	// If no such tuple pair, add one.
	if pairRef == nil {
		pairNode = tview.NewTreeNode(pwru.GetTuple(tuple(e), true))
		pairNode.SetColor(tcell.ColorGreen)
		pairNode.SetReference(e)
		pairNode.SetExpanded(false)
		root.AddChild(pairNode)
	}

	fn := addr2Name.Addr2NameMap[e.Addr].Name()
	flowNode := tview.NewTreeNode(fmt.Sprintf(dir+"%s", fn)).SetColor(tcell.ColorPink)
	flowNode.SetReference(e)

	pairNode.AddChild(flowNode)
}
