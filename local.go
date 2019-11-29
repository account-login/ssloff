package ssloff

import (
	"bufio"
	"context"
	"crypto/tls"
	"gopkg.in/account-login/ctxlog.v2"
	"net"
	"sync/atomic"
	"time"
)

type Local struct {
	// params
	RemoteAddr  string
	LocalAddr   string
	DialTimeout float64
	MITM        *MITM
	// *peerState
	pstate atomic.Value
}

func (l *Local) Start(ctx context.Context) error {
	// init atomic.Value
	l.pstate.Store((*peerState)(nil))

	// listen for client
	listener, err := net.Listen("tcp", l.LocalAddr)
	if err != nil {
		return err
	}
	go l.clientAcceptor(ctx, listener)

	// connect to remote
	go l.remoteConnector(ctx)

	return nil
}

func (l *Local) clientAcceptor(ctx context.Context, listener net.Listener) {
	defer safeClose(ctx, listener)

	session := uint64(0)
	for {
		session++

		conn, err := listener.Accept()
		if err != nil {
			ctxlog.Errorf(ctx, "accept: %v", err)
			continue
		}

		ctx := ctxlog.Pushf(ctx, "[session:%v][client:%v]", session, conn.RemoteAddr())
		go l.clientInitializer(ctx, conn)
	}
}

func (l *Local) clientInitializer(ctx context.Context, conn net.Conn) {
	defer safeClose(ctx, conn)

	acceptedUs := time.Now().UnixNano() / 1000
	ctxlog.Infof(ctx, "accepted")

	// get remote state
	p := l.pstate.Load().(*peerState)
	if p == nil {
		ctxlog.Errorf(ctx, "peer not ready")
		return
	}

	// read socks5 req
	// TODO: io deadline
	// TODO: http proxy
	reader := bufio.NewReaderSize(conn, kReaderBuf)
	dstAddr, dstPort, err := socks5handshake(readerWriter{reader, conn})
	if err != nil {
		ctxlog.Errorf(ctx, "%v", err)
		return
	}

	// detect ssl
	var tlsConn *tls.Conn
	// consume buffered data
	peekData := make([]byte, reader.Buffered())
	_, _ = reader.Read(peekData)
	if l.MITM != nil && dstPort == 443 {
		// read more data
		if len(peekData) == 0 {
			peekData = make([]byte, kReaderBuf)
			n, err := conn.Read(peekData)
			if err != nil {
				ctxlog.Errorf(ctx, "peek for ssl handshake: %v", err)
				return
			}

			peekData = peekData[:n]
		}

		if host, ok := detectTLS(peekData); ok {
			// setup peekedConn
			if host == "" {
				host = dstAddr.String()
				ctxlog.Infof(ctx, "got tls without SNI [host:%v]", host)
			} else {
				ctxlog.Infof(ctx, "got tls SNI [host:%v]", host)
			}
			bottom := peekedConn{peeked: peekData, conn: conn}
			peekData = nil
			// create tls conn
			tlsConn = tls.Server(&bottom, l.MITM.TLSForHost(ctx, host))
			// fix dstAddr to domain name if tls host is domain name
			if dstAddr.atype != kSocksAddrDomain {
				if net.ParseIP(host) == nil {
					ctxlog.Infof(ctx, "fix [dst:%v] to [host:%v]", dstAddr, host)
					dstAddr = socksAddr{atype: kSocksAddrDomain, addr: []byte(host)}
				}
			}
		}
	}

	// create client
	client := createClient(ctx, p)
	if client == nil {
		return
	}
	defer client.leafClose(ctx)

	// log
	ctx = ctxlog.Pushf(ctx, "[client][id:%v][target:%v:%v]", client.id, dstAddr, dstPort)
	ctxlog.Debugf(ctx, "created client")

	// setup client
	if tlsConn != nil {
		client.conn = tlsConn
	} else {
		client.conn = conn
	}
	client.metric.Id = client.id
	client.metric.Leaf = socksAddrString(dstAddr, dstPort)
	atomic.StoreInt64(&client.metric.Created, acceptedUs)

	// connect cmd
	var cmd uint32 = kCmdConnect
	if tlsConn != nil {
		cmd = kCmdConnectSSL
	}
	client.peerWriterInput(ctx, &protoMsg{
		cmd: cmd, cid: client.id, data: serializeSocksAddr(dstAddr, dstPort),
	})

	// peeked data
	if len(peekData) > 0 {
		ctxlog.Debugf(ctx, "client reader got %v bytes from peekData", len(peekData))
		client.peerWriterInput(ctx, &protoMsg{
			cmd: kCmdData, cid: client.id, data: peekData,
		})
		client.metric.FirstRead = time.Now().UnixNano() / 1000
		atomic.AddInt64(&client.metric.BytesRead, int64(len(peekData)))
	}

	// start client io
	go client.leafReader(ctx)
	go client.leafWriter(ctx)

	// wait for client done
	<-client.readerDone
	<-client.writerDone

	// clear client state
	ctxlog.Infof(ctx, "client done")
}

func createClient(ctx context.Context, p *peerState) *leafState {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.quiting {
		ctxlog.Warnf(ctx, "can not create leaf since peer is quiting")
		return nil
	}

	// find next id
	for _, ok := p.leafStates[p.clientIdSeq]; ok; p.clientIdSeq++ {
		ctxlog.Debugf(ctx, "[clientIdSeq:%v] overflowed", p.clientIdSeq)
	}

	// create client
	l := p.newLeaf()
	l.id = p.clientIdSeq
	l.peer = p
	l.fc.win = kDefaultWindow // TODO: config
	p.leafStates[l.id] = l

	// next id
	p.clientIdSeq++
	return l
}

func (l *Local) remoteConnector(ctx context.Context) {
	session := uint64(0)
	for {
		session++
		ctx := ctxlog.Pushf(ctx, "[rsession:%v]", session)

		l.remoteInitializer(ctx)

		ctxlog.Warnf(ctx, "reconnecting after 1s")
		time.Sleep(1 * time.Second)
	}
}

func (l *Local) remoteInitializer(ctx context.Context) {
	// TODO: io timeout
	dialTMO := time.Duration(float64(time.Second) * l.DialTimeout)
	conn, err := net.DialTimeout("tcp", l.RemoteAddr, dialTMO)
	if err != nil {
		ctxlog.Errorf(ctx, "connect remote: %v", err)
		return
	}
	defer safeClose(ctx, conn)

	ctxlog.Infof(ctx, "[remote:%v] connected from [local:%v]", l.RemoteAddr, conn.LocalAddr())

	p := newPeer()
	p.conn = conn
	p.clientIdSeq = 1 // client id starts from 1

	// init remote
	go p.peerReader(ctx)
	go p.peerWriter(ctx)

	// store remote
	l.pstate.Store(p)

	// dbg server
	dbgServerSetPeer(p)

	// wait remote down
	<-p.readerDone
	<-p.writerDone

	// clear remote state
	l.pstate.Store((*peerState)(nil))
	p.peerClose(ctx)
}
