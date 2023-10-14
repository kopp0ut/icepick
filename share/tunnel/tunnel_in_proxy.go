package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/kopp0ut/icepick/share/cio"
	"github.com/kopp0ut/icepick/share/settings"

	"golang.org/x/crypto/ssh"
)

// sshTunnel exposes a subset of Tunnel to subtypes
type sshTunnel interface {
	getSSH(ctx context.Context) ssh.Conn
}

// Proxy is the inbound portion of a Tunnel
type Proxy struct {
	sshTun sshTunnel
	id     int
	count  int
	remote *settings.Remote
	dialer net.Dialer
	tcp    *net.TCPListener
	udp    *udpListener
	mu     sync.Mutex
}

// NewProxy creates a Proxy
func NewProxy(sshTun sshTunnel, index int, remote *settings.Remote) (*Proxy, error) {
	id := index + 1
	p := &Proxy{
		sshTun: sshTun,
		id:     id,
		remote: remote,
	}
	return p, p.listen()
}

func (p *Proxy) listen() error {
	if p.remote.Stdio {
		//TODO check if pipes active?
	} else if p.remote.LocalProto == "tcp" {
		addr, err := net.ResolveTCPAddr("tcp", p.remote.LocalHost+":"+p.remote.LocalPort)
		if err != nil {
			return err
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return err
		}
		p.tcp = l
	} else if p.remote.LocalProto == "udp" {
		l, err := listenUDP(p.sshTun, p.remote)
		if err != nil {
			return err
		}

		p.udp = l
	} else {
		return fmt.Errorf("unknown local proto")
	}
	return nil
}

// Run enables the proxy and blocks while its active,
// close the proxy by cancelling the context.
func (p *Proxy) Run(ctx context.Context) error {
	if p.remote.Stdio {
		return p.runStdio(ctx)
	} else if p.remote.LocalProto == "tcp" {
		return p.runTCP(ctx)
	} else if p.remote.LocalProto == "udp" {
		return p.udp.run(ctx)
	}
	panic("should not get here")
}

func (p *Proxy) runStdio(ctx context.Context) error {
	for {
		p.pipeRemote(ctx, cio.Stdio)
		select {
		case <-ctx.Done():
			return nil
		default:
			// the connection is not ready yet, keep waiting
		}
	}
}

func (p *Proxy) runTCP(ctx context.Context) error {
	done := make(chan struct{})
	//implements missing net.ListenContext
	go func() {
		select {
		case <-ctx.Done():
			p.tcp.Close()
		case <-done:
		}
	}()
	for {
		src, err := p.tcp.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				//listener closed
				err = nil
			default:
			}
			close(done)
			return err
		}
		go p.pipeRemote(ctx, src)
	}
}

func (p *Proxy) pipeRemote(ctx context.Context, src io.ReadWriteCloser) {
	defer src.Close()

	p.mu.Lock()
	p.count++

	p.mu.Unlock()

	sshConn := p.sshTun.getSSH(ctx)
	if sshConn == nil {

		return
	}
	//ssh request for tcp connection for this proxy's remote
	dst, reqs, err := sshConn.OpenChannel("chisel", []byte(p.remote.Remote()))
	if err != nil {

		return
	}
	go ssh.DiscardRequests(reqs)
	//then pipe
	_, _ = cio.Pipe(src, dst)

}
