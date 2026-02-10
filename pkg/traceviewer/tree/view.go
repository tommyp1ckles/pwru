package tree

import "strings"

type TreeView struct {
	selected *node
	cursor   int
	start    int
	end      int

	root *node
}

func NewTreeView() *TreeView {
	return &TreeView{
		cursor: 0,
		root:   newNode(),
		start:  0,
		end:    10,
	}
}

// traversePreOrderRange returns nodes in pre-order traversal within the specified [start, end) index range.
func (tv *TreeView) traversePreOrderRange(start, end int) []traversalNode {
	if tv.root == nil || start < 0 || start >= tv.root.size {
		return nil
	}
	if end <= start {
		return nil
	}
	return tv.root.traversePreOrderRange(start, end, 0, 0)
}

// upsert ensures the root exists and inserts or updates a path starting from the root.
func (tv *TreeView) Upsert(e *Event, collapse bool, index func(depth int) (string, bool)) {
	if tv.root == nil {
		tv.root = &node{str: "root", size: 1}
	}
	tv.root.upsert(e, collapse, index, 0)
}

func (t *TreeView) View() string {
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

		checkbox := "☐"
		if i == cursorIndex {
			checkbox = "■"
			t.selected = tn.n
		}

		b.WriteString(pre + expandIndicator + checkbox + " " + tn.n.str + "\n")
	}

	return b.String()
}

func (tv *TreeView) GetSelectedLeafSize() int {
	if tv.selected == nil {
		return 0
	}
	return tv.selected.leafSize
}

func (tv *TreeView) GetRootRealSize() int {
	return tv.root.realSize
}

func (tv *TreeView) SortSelected() {
	if tv.selected == nil {
		return
	}
	tv.selected.Sort()
}

func (tv *TreeView) GetSelected() *PktView {
	if tv.selected == nil {
		return nil
	}
	return tv.selected.pkt
}

func (tv *TreeView) ActionUp() {
	if tv.cursor > 0 {
		tv.cursor--
		if tv.cursor < tv.start {
			tv.start--
			tv.end--
		}
	}
}

func (tv *TreeView) ActionDown() {
	if tv.cursor < tv.root.size-2 {
		tv.cursor++
		if tv.cursor >= tv.end {
			tv.start++
			tv.end++
		}
	}
}

func (tv *TreeView) SetCursor(c int) {
	tv.cursor = c
}

func (tv *TreeView) ToggleCollapsedSelected() {
	if tv.selected == nil {
		return
	}
	tv.selected.setCollapsed(!tv.selected.collapsed)
}

func (tv *TreeView) SetEnd(h int) {
	tv.end = h
}
