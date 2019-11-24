package ssloff

import (
	"context"
	"crypto/tls"
	"gopkg.in/account-login/ctxlog.v2"
	"net"
	"strings"
	"time"
)

type Remote struct {
	// param
	RemoteAddr string
	PreferIPv4 bool
}

func (r *Remote) Start(ctx context.Context) error {
	// listen for local
	listener, err := net.Listen("tcp", r.RemoteAddr)
	if err != nil {
		return err
	}

	go r.localAcceptor(ctx, listener)
	return nil
}

func (r *Remote) localAcceptor(ctx context.Context, listener net.Listener) {
	defer safeClose(ctx, listener)

	session := uint64(0)
	for {
		session++

		conn, err := listener.Accept()
		if err != nil {
			ctxlog.Errorf(ctx, "accept: %v", err)
			continue
		}

		ctx := ctxlog.Pushf(ctx, "[session:%v][local:%v]", session, conn.RemoteAddr())
		go r.localInitializer(ctx, conn)
	}
}

func (r *Remote) localInitializer(ctx context.Context, conn net.Conn) {
	defer safeClose(ctx, conn)

	ctxlog.Infof(ctx, "accepted")

	// create peerState
	p := newPeer()
	p.conn = conn
	p.onConnect = func(ctx context.Context, cid uint32, cmd uint32, addr socksAddr, port uint16) {
		// create leaf synchronously
		l := createTarget(ctx, p, cid)
		if l == nil {
			return
		}
		// connect to target asynchronously
		go doConnect(r, l, ctx, cmd, addr, port)
	}

	// start io
	go p.peerReader(ctx)
	go p.peerWriter(ctx)

	// wait for reader and writer
	<-p.readerDone
	<-p.writerDone

	// clear peer state
	p.peerClose(ctx)
	ctxlog.Infof(ctx, "done")
}

func createTarget(ctx context.Context, p *peerState, cid uint32) *leafState {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.quiting {
		ctxlog.Warnf(ctx, "can not create target: peer is quiting")
		return nil
	}

	if p.leafStates[cid] != nil {
		ctxlog.Errorf(ctx, "[LOCAL_BUG] [cid:%v] exists", cid)
		return nil
	}

	// create leafState
	l := newLeaf()
	l.id = cid
	l.peer = p
	l.fc.win = kDefaultWindow // TODO: conf
	p.leafStates[cid] = l
	return l
}

func doConnect(remote *Remote, l *leafState,
	ctx context.Context, cmd uint32, dstAddr socksAddr, dstPort uint16) {

	defer l.leafClose(ctx)
	addr := socksAddrString(dstAddr, dstPort)

	// metric
	l.metric.Id = l.id
	l.metric.Leaf = addr
	l.metric.Created = time.Now().UnixNano() / 1000

	// dial
	ctx = ctxlog.Pushf(ctx, "[cid:%v][target:%s]", l.id, addr)
	conn, err := dial(ctx, addr, remote.PreferIPv4)
	if err != nil {
		ctxlog.Errorf(ctx, "target dial: %v", err)
		l.peer.leafExitingInput(&protoMsg{cmd: kCmdClose, cid: l.id})
		return
	}
	l.metric.Connected = time.Now().UnixNano() / 1000
	defer safeClose(ctx, conn) // NOTE: will closing the net.Conn, not tls.Conn

	// tls
	if cmd == kCmdConnectSSL {
		if dstAddr.atype != kSocksAddrDomain {
			ctxlog.Errorf(ctx, "[LOCAL_BUG] kCmdConnectSSL requires ServerName")
			l.peer.leafExitingInput(&protoMsg{cmd: kCmdClose, cid: l.id})
			return
		}
		conn = tls.Client(conn, &tls.Config{ServerName: string(dstAddr.addr)})
		// NOTE: tls.Conn will not be closed, see comment above
	}

	// connected
	ctxlog.Infof(ctx, "target connected")
	l.conn = conn

	// start leaf io
	go l.leafReader(ctx)
	go l.leafWriter(ctx)

	// wait for leaf done
	<-l.readerDone
	<-l.writerDone
	ctxlog.Infof(ctx, "target done")
}

func isIPv6(dstAddr socksAddr) bool {
	switch dstAddr.atype {
	case kSocksAddrIPV4:
		return false
	case kSocksAddrIPV6:
		return true
	case kSocksAddrDomain:
		// firefox bug, request ipv6 addr as domain addr
		return strings.ContainsRune(string(dstAddr.addr), ':')
		//ip := net.ParseIP(string(dstAddr.addr))
		//return ip != nil && ip.To4() == nil
	default:
		panic("bad atype")
	}
}

func dial(ctx context.Context, addr string, preferV4 bool) (conn net.Conn, err error) {
	d := &net.Dialer{Timeout: 2 * time.Second} // TODO: config
	nets := []string{"tcp"}
	if preferV4 {
		nets = []string{"tcp4", "tcp"}
	}
	for _, network := range nets {
		if conn, err = d.DialContext(ctx, network, addr); err == nil {
			return
		}
		if len(nets) > 1 {
			ctxlog.Debugf(ctx, "try dial %s: %v", network, err)
		}
	}
	return
}
