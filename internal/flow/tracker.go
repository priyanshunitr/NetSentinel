package flow

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"netsentinel/internal/model"
)

type Key struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string
}

func KeyFor(p model.PacketInfo) Key {
	return Key{p.SrcIP, p.DstIP, p.SrcPort, p.DstPort, strings.ToUpper(p.Protocol)}
}

func (k Key) ID() string {
	value := net.JoinHostPort(k.SrcIP, strconv.Itoa(int(k.SrcPort))) + "|" + net.JoinHostPort(k.DstIP, strconv.Itoa(int(k.DstPort))) + "|" + k.Protocol
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type entry struct {
	flow    model.Flow
	touched time.Time
}

// Tracker is owned by store.Memory and protected by that store's mutex. There
// is no second lock or independent writer. Flows are directional 5-tuples.
type Tracker struct {
	entries  map[string]*list.Element
	recent   *list.List
	capacity int
	idle     time.Duration
	evicted  uint64
}

func New(capacity int, idle time.Duration) *Tracker {
	return &Tracker{entries: make(map[string]*list.Element), recent: list.New(), capacity: capacity, idle: idle}
}

func (t *Tracker) Observe(p model.PacketInfo, now time.Time) {
	if p.Protocol != "TCP" && p.Protocol != "UDP" {
		return
	}
	id := KeyFor(p).ID()
	element, exists := t.entries[id]
	if !exists {
		if len(t.entries) >= t.capacity {
			t.remove(t.recent.Back())
			t.evicted++
		}
		element = t.recent.PushFront(&entry{flow: model.Flow{ID: id, SrcIP: p.SrcIP, DstIP: p.DstIP, SrcPort: p.SrcPort, DstPort: p.DstPort, Protocol: p.Protocol, FirstSeen: p.Timestamp, LastSeen: p.Timestamp}})
		t.entries[id] = element
	}
	item := element.Value.(*entry)
	item.touched = now
	t.recent.MoveToFront(element)
	if p.Timestamp.Before(item.flow.FirstSeen) {
		item.flow.FirstSeen = p.Timestamp
	}
	if p.Timestamp.After(item.flow.LastSeen) {
		item.flow.LastSeen = p.Timestamp
	}
	item.flow.PacketCount++
	if p.PacketSize > 0 {
		item.flow.ByteCount += uint64(p.PacketSize)
	}
	if p.SYN {
		item.flow.SynCount++
	}
	if p.ACK {
		item.flow.AckCount++
	}
	if p.FIN {
		item.flow.FinCount++
	}
	if p.RST {
		item.flow.RstCount++
	}
}

func (t *Tracker) Expire(now time.Time) {
	for element := t.recent.Back(); element != nil; element = t.recent.Back() {
		if now.Sub(element.Value.(*entry).touched) < t.idle {
			break
		}
		t.remove(element)
	}
}

func (t *Tracker) remove(element *list.Element) {
	delete(t.entries, element.Value.(*entry).flow.ID)
	t.recent.Remove(element)
}

func (t *Tracker) Get(id string) (model.Flow, bool) {
	element, ok := t.entries[id]
	if !ok {
		return model.Flow{}, false
	}
	return element.Value.(*entry).flow, true
}

func (t *Tracker) Recent(limit int) []model.Flow {
	result := make([]model.Flow, 0, min(limit, t.Len()))
	for element := t.recent.Front(); element != nil && len(result) < limit; element = element.Next() {
		result = append(result, element.Value.(*entry).flow)
	}
	return result
}

func (t *Tracker) Len() int        { return len(t.entries) }
func (t *Tracker) Evicted() uint64 { return t.evicted }
