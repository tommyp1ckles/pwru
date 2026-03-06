package tree

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpsert(t *testing.T) {
	type eventInput struct {
		event    *Event
		path     []string
		collapse bool
	}
	tests := []struct {
		name             string
		events           []eventInput
		expectedRealSize int
		expectedLeafSize int
		expectedSize     int
	}{
		{
			name: "single event uncollapsed",
			events: []eventInput{
				{
					event:    &Event{},
					path:     []string{"a", "b"},
					collapse: false,
				},
			},
			expectedRealSize: 4, // root, a, b, leaf
			expectedLeafSize: 1,
			expectedSize:     4,
		},
		{
			name: "single event collapsed",
			events: []eventInput{
				{
					event:    &Event{},
					path:     []string{"a", "b"},
					collapse: true,
				},
			},
			expectedRealSize: 4,
			expectedLeafSize: 1,
			expectedSize:     2, // root(not collapsed) -> a(collapsed, size 1)
		},
		{
			name: "multiple events sharing path uncollapsed",
			events: []eventInput{
				{
					event:    &Event{},
					path:     []string{"x", "y"},
					collapse: false,
				},
				{
					event:    &Event{},
					path:     []string{"x", "z"},
					collapse: false,
				},
			},
			expectedRealSize: 6, // root, x, y, leaf1, z, leaf2
			expectedLeafSize: 2,
			expectedSize:     6, // root(1) + x(1 + y(2) + z(2)) = 6
		},
		{
			name: "multiple events sharing path collapsed",
			events: []eventInput{
				{
					event:    &Event{},
					path:     []string{"x", "y"},
					collapse: true,
				},
				{
					event:    &Event{},
					path:     []string{"x", "z"},
					collapse: true,
				},
			},
			expectedRealSize: 6,
			expectedLeafSize: 2,
			expectedSize:     2, // root(1) + x(1 because collapsed) = 2
		},
		{
			name: "original complex case",
			events: func() []eventInput {
				var events []eventInput
				for i := range 6 {
					path := []string{"x"}
					if i%2 == 0 {
						path = append(path, "even")
					} else {
						path = append(path, "odd")
					}
					events = append(events, eventInput{
						event:    &Event{Skb: strconv.Itoa(i)},
						path:     path,
						collapse: true,
					})
				}
				return events
			}(),
			expectedRealSize: 10,
			expectedLeafSize: 6,
			expectedSize:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newNode()
			for _, ei := range tt.events {
				r.upsert(ei.event, ei.collapse, func(depth int) (string, bool) {
					if depth < len(ei.path) {
						return ei.path[depth], true
					}
					return "", false
				}, 0)
			}
			assert.Equal(t, tt.expectedRealSize, r.realSize, "realSize mismatch")
			assert.Equal(t, tt.expectedLeafSize, r.leafSize, "leafSize mismatch")
			assert.Equal(t, tt.expectedSize, r.size, "size mismatch")
		})
	}
}
