package tunnel

import (
	"io"
	"net"

	"github.com/kopp0ut/icepick/share/cio"
	"github.com/kopp0ut/icepick/share/cnet"
	"github.com/kopp0ut/icepick/share/settings"

	"golang.org/x/crypto/ssh"
)

func (t *Tunnel) handleSSHRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "ping":
			r.Reply(true, []byte("pong"))
		default:
		}
	}
}

func (t *Tunnel) handleSSHChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		go t.handleSSHChannel(ch)
	}
}

func (t *Tunnel) handleSSHChannel(ch ssh.NewChannel) {
	if !t.Config.Outbound {
		ch.Reject(ssh.Prohibited, "Denied outbound connection")
		return
	}
	remote := string(ch.ExtraData())
	//extract protocol
	hostPort, proto := settings.L4Proto(remote)
	udp := proto == "udp"
	socks := hostPort == "socks"
	if socks && t.socksServer == nil {
		ch.Reject(ssh.Prohibited, "SOCKS5 is not enabled")
		return
	}
	sshChan, reqs, err := ch.Accept()
	if err != nil {

		return
	}
	stream := io.ReadWriteCloser(sshChan)
	//cnet.MeterRWC(t.Logger.Fork("sshchan"), sshChan)
	defer stream.Close()
	go ssh.DiscardRequests(reqs)

	//ready to handle
	t.connStats.Open()

	if socks {
		err = t.handleSocks(stream)
	} else if udp {
		err = t.handleUDP(stream, hostPort)
	} else {
		err = t.handleTCP(stream, hostPort)
	}
	t.connStats.Close()

}

func (t *Tunnel) handleSocks(src io.ReadWriteCloser) error {
	return t.socksServer.ServeConn(cnet.NewRWCConn(src))
}

func (t *Tunnel) handleTCP(src io.ReadWriteCloser, hostPort string) error {
	dst, err := net.Dial("tcp", hostPort)
	if err != nil {
		return err
	}
	_, _ = cio.Pipe(src, dst)
	return nil
}
