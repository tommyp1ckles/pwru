package models

import "time"

type Event struct {
	Skb         string     `json:"skb,omitempty"`
	Shinfo      string     `json:"skb_shared_info,omitempty"`
	CPU         uint32     `json:"cpu,omitempty"`
	Process     string     `json:"process,omitempty"`
	Func        string     `json:"func,omitempty"`
	CallerFunc  string     `json:"caller_func,omitempty"`
	Time        *time.Time `json:"time,omitempty"`
	Netns       uint32     `json:"netns,omitempty"`
	Mark        uint32     `json:"mark,omitempty"`
	Iface       string     `json:"iface,omitempty"`
	Proto       uint16     `json:"proto,omitempty"`
	MTU         uint32     `json:"mtu,omitempty"`
	Len         uint32     `json:"len,omitempty"`
	CB          [5]uint32  `json:"cb,omitempty"`
	Tuple       *Tuple     `json:"tuple,omitempty"`
	TunnelTuple *Tuple     `json:"tunnel_tuple,omitempty"`
	Stack       any        `json:"stack,omitempty"`
	SkbMetadata any        `json:"skb_metadata,omitempty"`
}

type Tuple struct {
	Saddr string `json:"saddr,omitempty"`
	Daddr string `json:"daddr,omitempty"`
	Sport uint16 `json:"sport,omitempty"`
	Dport uint16 `json:"dport,omitempty"`
	Proto uint8  `json:"proto,omitempty"`
	Flags string `json:"flags,omitempty"`
}
