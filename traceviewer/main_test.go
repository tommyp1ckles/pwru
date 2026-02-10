package main

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpsertRealsize(t *testing.T) {
	r := newNode()
	assert.Equal(t, r.realSize, 1)
	// Create a tree with root - 'x' that then diverges into
	// even and odd subtrees, containing the individual leaves.
	// Therefore the overhead is root + x + odd + even + 6 nodes = 10
	for i := range 6 {
		e := &Event{
			Addr: strconv.Itoa(i),
		}
		r.upsert(e, true, func(depth int) (string, bool) {
			switch depth {
			case 0:
				return "x", true
			case 1:
				if i%2 == 0 {
					return "even", true
				}
				return "odd", true
			default:
				return "", false
			}
		}, 0)
	}
	// 6 leafs, 2 even/odd nodes, one "x" nodes and root node
	assert.Equal(t, 6+2+1+1, r.realSize)
	assert.Equal(t, 6, r.leafSize)
}
