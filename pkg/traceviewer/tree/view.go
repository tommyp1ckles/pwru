// SPDX-License-Identifier: Apache-2.0

package tree

import "strings"

// TreeView is an interactive tui view that efficiently organizes
// folded nodes into a tree.
type TreeView struct {
	selected *node
	cursor   int
	start    int
	end      int

	root *node

	buf          string
	arrowIndices []int
	dirty        bool
}

// NewTreeView creates a new tree view with no nodes.
func NewTreeView() *TreeView {
	return &TreeView{
		cursor: 0,
		root:   newNode(),
		start:  0,
		end:    10,
		dirty:  true, // always draw first time.
	}
}

func (tv *TreeView) setDirty() {
	tv.dirty = true
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

// Upsert ensures the root exists and inserts or updates a path starting from the root.
func (tv *TreeView) Upsert(e *Event, collapse bool, index func(depth int) (string, bool)) {
	tv.setDirty()
	if tv.root == nil {
		tv.root = &node{str: "root", size: 1}
	}
	tv.root.upsert(e, collapse, index, 0)
}

const tabWidth = 2

func (t *TreeView) View() string {
	if !t.dirty {
		return t.buf
	}

	b := &strings.Builder{}
	t.arrowIndices = []int{}

	// We skip the root node when drawing.
	window := t.traversePreOrderRange(t.start+1, t.end+1)

	// Handle empty tree case
	if len(window) == 0 {
		b.WriteString("[empty tree]\n")
		return b.String()
	}

	// Calculate the cursor's position in the window (should be at index 10, or less if near start)
	cursorIndex := t.cursor - t.start

	// Draw each node in the window
	for i, tn := range window {
		// Indentation based on depth
		pre := strings.Repeat(" ", tabWidth*int(tn.depth))

		// Determine expander arrow
		expandIndicator := "  " // two spaces for leaf nodes (no children)
		if len(tn.n.children) > 0 {
			if tn.n.collapsed {
				expandIndicator = "▶ "
			} else {
				expandIndicator = "▼ "
			}

			t.arrowIndices = append(t.arrowIndices, len(pre))
		} else {
			t.arrowIndices = append(t.arrowIndices, -1)
		}

		checkbox := "☐"
		if i == cursorIndex {
			checkbox = "■"
			t.selected = tn.n
		}

		b.WriteString(pre + expandIndicator + checkbox + " " + tn.n.str + "\n")
	}

	t.buf = b.String()
	return t.buf
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
	tv.setDirty()
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

// ActionUp moves and possibly scrolls the cursor and viewport up.
func (tv *TreeView) ActionUp() {
	tv.setDirty()
	if tv.cursor > 0 {
		tv.cursor--
		if tv.cursor < tv.start {
			tv.start--
			tv.end--
		}
	}
}

// ActionDown moves and possibly scrolls the cursor and viewport down.
func (tv *TreeView) ActionDown() {
	tv.setDirty()
	if tv.cursor < tv.root.size-2 {
		tv.cursor++
		if tv.cursor >= tv.end {
			tv.start++
			tv.end++
		}
	}
}

// SetCursor overrides the current cursor position.
func (tv *TreeView) SetCursor(c int) {
	tv.setDirty()
	tv.cursor = c
}

// ToggleCollapsedSelected toggles the current selected nodes
// collapsed state.
func (tv *TreeView) ToggleCollapsedSelected() {
	tv.setDirty()
	if tv.selected == nil {
		return
	}
	tv.selected.setCollapsed(!tv.selected.collapsed)
}

func (tv *TreeView) SetEnd(h int) {
	tv.setDirty()
	tv.dirty = true
	tv.end = h
}

func (tv *TreeView) GetStart() int {
	return tv.start
}

func (tv *TreeView) ColIsArrow(col, row int) bool {
	if row < 0 || row >= len(tv.arrowIndices) {
		return false
	}
	if tv.arrowIndices[row] < 0 {
		return false
	}
	return tv.arrowIndices[row] == col
}
