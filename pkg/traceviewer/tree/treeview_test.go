package tree

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/cilium/pwru/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestTreeView(t *testing.T) {
	scenario1 := func(tv *TreeView) {
		for i := range 5 {
			e := &Event{
				Skb: "0xdeadbeef",
				Tuple: &models.Tuple{
					Sport: 50000 + uint16(i),
					Dport: 8080,
				},
			}
			tv.Upsert(e, false, func(depth int) (string, bool) {
				switch depth {
				case 0:
					return fmt.Sprintf("skb(%s)", e.Skb), true
				case 1:
					return strconv.Itoa(int(e.Tuple.Sport)), true
				case 2:
					return strconv.Itoa(int(e.Tuple.Dport)), true
				}
				return fmt.Sprintf("leaf(%s)", e.Skb), false
			})
		}
	}

	tests := []struct {
		name           string
		setup          func(tv *TreeView)
		actions        func(tv *TreeView)
		expectedView   string
		expectedCursor int
		expectedRootRS int
		start          int
		end            int
		cursor         int
	}{
		{
			name: "empty tree",
			setup: func(tv *TreeView) {
			},
			expectedView:   "[empty tree]\n",
			expectedCursor: 0,
			expectedRootRS: 1,
		},
		{
			name: "single event",
			setup: func(tv *TreeView) {
				e := &Event{Skb: "0xdeadbeef"}
				tv.Upsert(e, false, func(depth int) (string, bool) {
					switch depth {
					case 0:
						return fmt.Sprintf("skb(%s)", e.Skb), true
					}
					return fmt.Sprintf("leaf(%s)", e.Skb), false
				})
			},
			expectedView: "  ▼ ■ skb(0xdeadbeef)\n" +
				"      ☐ leaf(0xdeadbeef)\n",
			expectedCursor: 0,
			expectedRootRS: 4,
		},
		{
			// Will create 5 events and insert them into the tree with the folding of skb.sport.dport.
			// Note: Will only show the first ten lines.
			name:  "multi event",
			setup: scenario1,
			expectedView: `  ▼ ■ skb(0xdeadbeef)
    ▼ ☐ 50000
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50001
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50002
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
`,
			expectedCursor: 0,
			expectedRootRS: 4,
		},
		{
			// Will create 5 events and insert them into the tree with the folding of skb.sport.dport.
			// Note: Will only show the first ten lines.
			name:   "multi event change cursor",
			cursor: 3,
			setup:  scenario1,
			expectedView: `  ▼ ☐ skb(0xdeadbeef)
    ▼ ☐ 50000
      ▼ ☐ 8080
          ■ leaf(0xdeadbeef)
    ▼ ☐ 50001
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50002
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
`,
			expectedCursor: 0,
			expectedRootRS: 4,
		},
		{
			// Will create 5 events as above, but has a viewport of 20, so all lines should show up.
			name:  "multi event longer viewport",
			end:   20,
			setup: scenario1,
			expectedView: `  ▼ ■ skb(0xdeadbeef)
    ▼ ☐ 50000
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50001
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50002
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50003
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
    ▼ ☐ 50004
      ▼ ☐ 8080
          ☐ leaf(0xdeadbeef)
`,
			expectedCursor: 0,
			expectedRootRS: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tv := NewTreeView()
			if tt.setup != nil {
				tt.setup(tv)
			}
			if tt.actions != nil {
				tt.actions(tv)
			}

			if tt.start != 0 {
				tv.start = tt.start
			}
			if tt.end != 0 {
				tv.end = tt.end
			}

			if tt.cursor != 0 {
				tv.SetCursor(tt.cursor)
			}

			view := tv.View()
			if tt.expectedView != "" {
				assert.Equal(t, tt.expectedView, view)
			}

			t.Log(view)
		})
	}
}
