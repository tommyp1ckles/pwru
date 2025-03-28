package tui

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/pwru/internal/byteorder"
	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/tui/draw"
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
func App(addr2Name pwru.Addr2Name) (*tview.Application, *tview.TreeNode) {
	app := tview.NewApplication()
	/*flex := tview.NewFlex().
	AddItem(tview.NewBox().SetBorder(true).SetTitle("Left (1/2 x width of Top)"), 0, 1, false).
	AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewBox().SetBorder(true).SetTitle("Top"), 0, 1, false).
		AddItem(tview.NewBox().SetBorder(true).SetTitle("Middle (3 x height of Top)"), 0, 3, false).
		AddItem(tview.NewBox().SetBorder(true).SetTitle("Bottom (5 rows)"), 5, 1, false), 0, 2, false).
	AddItem(tview.NewBox().SetBorder(true).SetTitle("Right (20 cols)"), 20, 1, false)*/

	tree := tview.NewTreeView()

	// Create the root node
	root := tview.NewTreeNode("traces").
		SetColor(tcell.ColorBlue)

	// Ok, lets aggregate on tuple (bi directional).
	//
	// Goals:
	//	* Make it easy to trace through particular connections, without too much pcap/grep filtering.
	//	* Provide context where possible.
	//
	// i.e. 1.2.3.4:2222 <-> 1.1.1.1:1111
	// 	* Under this we group by contiguous skb address
	// 1.2.3.4:2222 <-> 1.1.1.1:1111:
	//	* 0xdeadbeefdeadbeef
	//		* (0) eth0 (container x outer)
	//		* (1) cilium_host
	//		* (2) 2025-01-1...
	//	* 0xffffffffffffffff
	//		* (0) 2025-01-1...
	//
	// These leaves select the pkt view:
	// skb:		0xdeadbeef00000000
	// tuple:	1.2.3.4:2222 <-> 1.1.1.1:1111:
	// mark:	0xffff # we can try to do cilium integration here:
	//		[0 1 0 0 0 0 0 0]
	//		  |
	// 		  MARK_IDENTITY
	// device: 	eth0:123 # note: would be nice to associate these better.
	//	* veth-pair: eth0:123 -> netns(1234):eth777
	//
	// Finally, we also take into account tunnel tuples for this.
	//
	// So top level we see a tuple, this is deep traced under both

	// Add child nodes
	/*child1 := tview.NewTreeNode("10.0.0.0:30124 ↔ 10.123.111.1:1234 ").
		SetColor(tcell.ColorGreen)

	skb1 := tview.NewTreeNode("0xdeadbeefdeadbeef")
	sample1 := tview.NewTreeNode("(0) eth0")
	sample2 := tview.NewTreeNode("(1) eth0")
	skb1.AddChild(sample1)
	skb1.AddChild(sample2)
	child1.AddChild(skb1)
	child3 := tview.NewTreeNode("10.123.111.1:1234 ↔ 10.0.0.0:30124 ").
		SetColor(tcell.ColorGreen)*/

	// Attach children to the root
	//root.AddChild(child1).
	//AddChild(child3)

	/*Insert(root, &pwru.Event{
		Addr: 1,
		Tuple: pwru.Tuple{
			L3Proto: syscall.ETH_P_IP,
			Saddr:   [16]byte{10, 0, 0, 1},
			Daddr:   [16]byte{10, 0, 0, 2},
			Sport:   30001,
			Dport:   1234,
		},
	})

	Insert(root, &pwru.Event{
		Addr: 1,
		Tuple: pwru.Tuple{
			L3Proto: syscall.ETH_P_IP,
			Saddr:   [16]byte{10, 0, 0, 1},
			Daddr:   [16]byte{10, 0, 0, 2},
			Sport:   30001,
			Dport:   1234,
		},
	})*/

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
			e.Meta.Mark = 0xffff
			mark := fmt.Sprintf("0x%08x", e.Meta.Mark)
			masks := decodeMark(uint16(e.Meta.Mark))
			ifindex := fmt.Sprintf("%d", e.Meta.Ifindex)
			fn := addr2Name.Addr2NameMap[e.Addr].Name()

			/*padr := func(s string, nesting int) string {
				nestOff := nesting * 2
				return strings.Repeat(" ", maxLen-(38+len(s))-nestOff)
			}*/

			portStr := func(n uint16) string {
				return strconv.Itoa(int(byteorder.NetworkToHost16(n)))
			}
			saddr := addrToStr(e.Tuple.L3Proto, e.Tuple.Saddr) + ":" + portStr(e.Tuple.Sport)
			daddr := addrToStr(e.Tuple.L3Proto, e.Tuple.Daddr) + ":" + portStr(e.Tuple.Dport)

			w := 70
			txt := draw.Header(w) + "\n"
			txt += draw.Line(w, " SKB:") + "\n"
			// todo line break
			txt += draw.Line(w, " skb_addr:"+skbAddr) + "\n"
			txt += draw.Line(w, " mark:"+mark) + "\n"
			for _, mask := range masks {
				txt += draw.Line(w, " *"+mask) + "\n"
			}
			txt += draw.Line(w, " ifindex:"+ifindex) + "\n"
			txt += draw.Line(w, " func_name:"+fn) + "\n"
			txt += draw.Line(w, " saddr:"+saddr) + "\n"
			txt += draw.Line(w, " daddr:"+daddr) + "\n"
			txt += draw.Footer(w)

			pktView.SetText(txt)
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
		AddItem(tree, 70, 2, true).
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

// Proposal: Fold operation, for a node holding a event ptr, we can fold that by any thing in there
// For example. Event{}.FoldBySource(1234), FoldByTimeChunk(5*time.Minute).
func Insert(root *tview.TreeNode, e *pwru.Event, addr2Name pwru.Addr2Name) {
	tuplePairs := root.GetChildren()
	var pairRef *pwru.Event
	// Pair node folds on 4-tuple (todo: make this for both directions).
	var pairNode *tview.TreeNode
	dir := "→"
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
		eq := equals(tp.Tuple, e.Tuple)
		revEq := equals(revTuple(tp.Tuple), e.Tuple)
		if revEq {
			dir = "←"
		}
		if eq || revEq {
			pairRef = tp
			pairNode = tpn
			break
		}
	}
	// If no such tuple pair, add one.
	if pairRef == nil {
		pairNode = tview.NewTreeNode(pwru.GetTupleData(e, true))
		pairNode.SetColor(tcell.ColorGreen)
		pairNode.SetReference(e)
		pairNode.SetExpanded(false)
		root.AddChild(pairNode)
	}

	ts := time.Now().Format(time.StampNano)
	fn := addr2Name.Addr2NameMap[e.Addr].Name()
	flowNode := tview.NewTreeNode(fmt.Sprintf(dir+"%s %s", fn, ts)).SetColor(tcell.ColorPink)
	flowNode.SetReference(e)

	pairNode.AddChild(flowNode)
}
