package tunnel

import (
	"encoding/gob"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kopp0ut/icepick/share/settings"
)

func (t *Tunnel) handleUDP(rwc io.ReadWriteCloser, hostPort string) error {
	conns := &udpConns{
		m: map[string]*udpConn{},
	}
	defer conns.closeAll()
	h := &udpHandler{
		hostPort: hostPort,
		udpChannel: &udpChannel{
			r: gob.NewDecoder(rwc),
			w: gob.NewEncoder(rwc),
			c: rwc,
		},
		udpConns: conns,
		maxMTU:   settings.EnvInt("UDP_MAX_SIZE", 9012),
	}

	for {
		p := udpPacket{}
		if err := h.handleWrite(&p); err != nil {
			return err
		}
	}
}

type udpHandler struct {
	hostPort string
	*udpChannel
	*udpConns
	maxMTU int
}

func (h *udpHandler) handleWrite(p *udpPacket) error {
	if err := h.r.Decode(&p); err != nil {
		return err
	}
	//dial now, we know we must write
	conn, exists, err := h.udpConns.dial(p.Src, h.hostPort)
	if err != nil {
		return err
	}
	//however, we dont know if we must read...
	//spawn up to <max-conns> go-routines to wait
	//for a reply.
	//TODO configurable
	//TODO++ dont use go-routines, switch to pollable
	//  array of listeners where all listeners are
	//  sweeped periodically, removing the idle ones
	const maxConns = 100
	if !exists {
		if h.udpConns.len() <= maxConns {
			go h.handleRead(p, conn)
		}
	}
	_, err = conn.Write(p.Payload)
	if err != nil {
		return err
	}
	return nil
}

func (h *udpHandler) handleRead(p *udpPacket, conn *udpConn) {
	//ensure connection is cleaned up
	defer h.udpConns.remove(conn.id)
	buff := make([]byte, h.maxMTU)
	for {
		//response must arrive within 15 seconds
		deadline := settings.EnvDuration("UDP_DEADLINE", 15*time.Second)
		conn.SetReadDeadline(time.Now().Add(deadline))
		//read response
		n, err := conn.Read(buff)
		if err != nil {

			break
		}
		b := buff[:n]
		//encode back over ssh connection
		err = h.udpChannel.encode(p.Src, b)
		if err != nil {
			return
		}
	}
}

type udpConns struct {
	sync.Mutex
	m map[string]*udpConn
}

func (cs *udpConns) dial(id, addr string) (*udpConn, bool, error) {
	cs.Lock()
	defer cs.Unlock()
	conn, ok := cs.m[id]
	if !ok {
		c, err := net.Dial("udp", addr)
		if err != nil {
			return nil, false, err
		}
		conn = &udpConn{
			id:   id,
			Conn: c, // cnet.MeterConn(cs.Logger.Fork(addr), c),
		}
		cs.m[id] = conn
	}
	return conn, ok, nil
}

func (cs *udpConns) len() int {
	cs.Lock()
	l := len(cs.m)
	cs.Unlock()
	return l
}

func (cs *udpConns) remove(id string) {
	cs.Lock()
	delete(cs.m, id)
	cs.Unlock()
}

func (cs *udpConns) closeAll() {
	cs.Lock()
	for id, conn := range cs.m {
		conn.Close()
		delete(cs.m, id)
	}
	cs.Unlock()
}

type udpConn struct {
	id string
	net.Conn
}
