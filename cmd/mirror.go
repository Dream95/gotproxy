package main

import (
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

type MirrorOptions struct {
	Enabled    bool
	Target     string
	Proto      string
	Timeout    time.Duration
	QueueSize  int
	DropOnFull bool
}

type mirrorMessage struct {
	network string
	payload []byte
}

type MirrorDispatcher struct {
	opts      MirrorOptions
	queue     chan mirrorMessage
	dropped   atomic.Uint64
	sent      atomic.Uint64
	sendError atomic.Uint64
}

func NewMirrorDispatcher(opts MirrorOptions) *MirrorDispatcher {
	if !opts.Enabled || opts.Target == "" {
		return nil
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 100 * time.Millisecond
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 1024
	}
	d := &MirrorDispatcher{
		opts:  opts,
		queue: make(chan mirrorMessage, opts.QueueSize),
	}
	go d.run()
	log.Printf("Mirror enabled: target=%s proto=%s direction=uplink queue=%d timeout=%s", opts.Target, opts.Proto, opts.QueueSize, opts.Timeout)
	return d
}

func (d *MirrorDispatcher) ShouldMirror(network string) bool {
	if d == nil {
		return false
	}
	return matchMirrorProto(d.opts.Proto, network)
}

func (d *MirrorDispatcher) Enqueue(network string, payload []byte) {
	if d == nil || len(payload) == 0 {
		return
	}
	msg := mirrorMessage{
		network: network,
		payload: append([]byte(nil), payload...),
	}
	if d.opts.DropOnFull {
		select {
		case d.queue <- msg:
		default:
			d.dropped.Add(1)
		}
		return
	}
	d.queue <- msg
}

func (d *MirrorDispatcher) run() {
	for msg := range d.queue {
		if err := d.send(msg); err != nil {
			d.sendError.Add(1)
			log.Printf("Mirror send failed (%s -> %s): %v", msg.network, d.opts.Target, err)
			continue
		}
		d.sent.Add(1)
	}
}

func (d *MirrorDispatcher) send(msg mirrorMessage) error {
	conn, err := net.DialTimeout(msg.network, d.opts.Target, d.opts.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(d.opts.Timeout))
	_, err = conn.Write(msg.payload)
	return err
}

func matchMirrorProto(config string, network string) bool {
	c := strings.ToLower(strings.TrimSpace(config))
	n := strings.ToLower(strings.TrimSpace(network))
	switch c {
	case "both":
		return n == "tcp" || n == "udp"
	case "tcp", "udp":
		return c == n
	default:
		return false
	}
}
