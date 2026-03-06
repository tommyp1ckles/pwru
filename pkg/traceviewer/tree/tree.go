package tree

import (
	"maps"
	"slices"
	"sort"

	"github.com/cilium/pwru/pkg/models"
)

type Event models.Event

type PktView struct {
	Event *Event
}

func newNode() *node {
	return &node{
		size:       1,
		realSize:   1,
		strToChild: make(map[string]*node),
	}
}

type node struct {
	collapsed bool
	realSize  int
	leafSize  int
	size      int
	cumSize   []int // always same size as children, cumSize[i] == sum(children[0...i].size)

	children   []*node
	strToChild map[string]*node
	parent     *node

	str string

	pkt *PktView
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

// Sort reorders children nodes under the tree based on their string
// values.
func (n *node) Sort() {
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
			child = &node{
				str:       key,
				size:      1,
				realSize:  1,
				parent:    n,
				collapsed: collapse,
			}
			n.children = append(n.children, child)
			n.strToChild[key] = child
		}
		child.upsert(e, collapse, index, depth+1)
	} else {
		leaf := &node{
			str:      key,
			size:     1,
			realSize: 1,
			leafSize: 1,
			parent:   n,
			pkt:      &PktView{e},
		}
		n.children = append(n.children, leaf)
	}

	// Maintain size and cumSize up the tree
	n.size = 1
	n.realSize = 1
	n.leafSize = 0
	if n.collapsed {
		n.cumSize = nil
	} else {
		n.cumSize = make([]int, len(n.children))
	}

	currentCumSize := 0
	for i, child := range n.children {
		n.realSize += child.realSize
		n.leafSize += child.leafSize

		if !n.collapsed {
			n.size += child.size
			currentCumSize += child.size
			n.cumSize[i] = currentCumSize
		}
	}
}
