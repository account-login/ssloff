package ssloff

import (
	"bufio"
	"context"
	"encoding/json"
	"gopkg.in/account-login/ctxlog.v2"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type peerMetric struct {
	Id                int64
	BytesRead         int64
	BytesWritten      int64
	LeavesCreateCount int64
	LeavesCloseCount  int64
	Leaves            map[string]leafMetric
}

type peerState struct {
	conn      net.Conn
	onConnect func(ctx context.Context, cid uint32, cmd uint32, dstAddr socksAddr, dstPort uint16)
	pmetric   peerMetric
	// reader
	readerExit chan struct{}
	readerDone chan struct{}
	// writer
	llist        SList // *leafState, notified leaves
	writerExit   chan struct{}
	writerNotify chan struct{}
	elist        SList // *protoMsg, exiting protoMsg
	writerDone   chan struct{}
	// leaves
	mu          sync.Mutex
	clientIdSeq uint32 // for local
	leafStates  map[uint32]*leafState
	quiting     bool
}

type leafMetric struct {
	Id           uint32
	Leaf         string
	Created      int64
	Connected    int64
	FirstWrite   int64
	FirstRead    int64
	LastRead     int64
	LastWrite    int64
	Closed       int64
	BytesRead    int64
	BytesWritten int64
}

type leafState struct {
	id     uint32
	conn   net.Conn
	peer   *peerState
	metric leafMetric
	// reader
	readerExit chan struct{}
	readerDone chan struct{}
	// writer
	writerInput SList // *protoMsg
	writerMutex sync.Mutex
	writerCond  sync.Cond
	writerDone  chan struct{}
	// peer writer queue
	mu      sync.Mutex
	cond    sync.Cond
	plist   SList // *protoMsg
	exiting bool
	// notified leaf queue, protected by peerState.mu
	llist    SLElement
	notified bool // is leaf is on peer's notification list?
	// flow control
	fc FlowCtrl
}

func newPeer() *peerState {
	return &peerState{
		readerExit:   make(chan struct{}, 4),
		readerDone:   make(chan struct{}, 4),
		writerNotify: make(chan struct{}, 4),
		writerExit:   make(chan struct{}, 4),
		writerDone:   make(chan struct{}, 4),
		leafStates:   map[uint32]*leafState{},
	}
}

func (p *peerState) newLeaf() *leafState {
	l := &leafState{
		readerExit: make(chan struct{}, 4),
		readerDone: make(chan struct{}, 4),
		writerDone: make(chan struct{}, 4),
	}
	l.writerCond.L = &l.writerMutex
	l.cond.L = &l.mu
	l.llist.Value = l
	atomic.AddInt64(&p.pmetric.LeavesCreateCount, 1)
	return l
}

func (p *peerState) peerExit() {
	p.readerExit <- struct{}{}
	p.writerExit <- struct{}{}
}

func (p *peerState) leafGet(cid uint32) *leafState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.leafStates[cid]
}

func (p *peerState) peerReader(ctx context.Context) {
	defer close(p.readerDone)

	reader := bufio.NewReaderSize(p.conn, kReaderBuf)
	ioInput, ioQuit := protoParser(reader)
	defer close(ioQuit)
	for {
		select {
		case ev := <-ioInput:
			// io error or eof
			if ev.err != nil {
				if ev.err != io.EOF {
					ctxlog.Errorf(ctx, "peer reader exit with io error: %v", ev.err)
				} else {
					ctxlog.Warnf(ctx, "peer reader exit with EOF")
				}
				p.peerExit()
				return
			}

			ctxlog.Debugf(ctx, "[cid:%v][cmd:%v][ack:%v][data_len:%v]",
				ev.cid, ev.cmd, ev.ack, len(ev.data))

			switch ev.cmd {
			case kCmdConnect, kCmdConnectSSL:
				// parse dst addr
				dstAddr, dstPort, err := parseSocksAddrData(ev.data)
				if err != nil {
					ctxlog.Errorf(ctx, "[cid:%v] cmd connect error: %v", ev.cid, err)
					p.peerExit()
					return
				}
				// new leaf
				if p.onConnect != nil {
					p.onConnect(ctx, ev.cid, ev.cmd, dstAddr, dstPort)
				} else {
					ctxlog.Warnf(ctx, "[REMOTE_BUG] got connect cmd from remote")
				}
				continue
			}

			// get leaf
			l := p.leafGet(ev.cid)
			if l == nil {
				ctxlog.Warnf(ctx, "[cid:%v] not exists", ev.cid)
				continue
			}
			switch ev.cmd {
			case kCmdData, kCmdEOF:
				l.leafUpdateAck(ev.ack)
				// TODO: check for window size
				ev.sle.Value = ev
				l.writerMutex.Lock()
				l.writerInput.PushBack(&ev.sle)
				l.writerCond.Signal()
				l.writerMutex.Unlock()
				// metric
				atomic.AddInt64(&l.peer.pmetric.BytesRead, int64(len(ev.data)))
			case kCmdClose:
				l.leafExit()
			default:
				ctxlog.Errorf(ctx, "[cid:%v] unknown [cmd:%v]", ev.cid, ev.cmd)
			}
		case <-p.readerExit:
			ctxlog.Infof(ctx, "peer reader exit with p.readerExit")
			return
		} // select
	} // for
}

func (p *peerState) leafDequeue(ctx context.Context) *leafState {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.llist.Empty() {
		return nil
	}
	l := p.llist.PopFront().Value.(*leafState)
	l.notified = false
	return l
}

func (p *peerState) leafConsume(ctx context.Context, l *leafState) error {
	var msg *protoMsg
	l.mu.Lock()
	exiting := l.exiting
	if !l.plist.Empty() {
		msg = l.plist.PopFront().Value.(*protoMsg)
		msg.ack = l.fc.rcv
	}
	l.mu.Unlock()

	if exiting {
		ctxlog.Debugf(ctx, "[cid:%v] ignoring exiting leaf", l.id)
		return nil
	}

	if msg == nil {
		ctxlog.Debugf(ctx, "[cid:%v] leaf wake up without event", l.id)
		return nil
	}

	// check msg
	switch msg.cmd {
	case kCmdConnect, kCmdConnectSSL, kCmdClose, kCmdEOF:
	case kCmdData:
		if len(msg.data) > kMsgRecvMaxLen {
			panic("ensure this")
		}
	default:
		panic("bad msg cmd")
	}

	// do write io
	if err := msg.writeTo(p.conn); err != nil {
		return err
	}

	// metric
	atomic.AddInt64(&l.peer.pmetric.BytesWritten, int64(len(msg.data)))

	// requeue leaf if leaf has more event
	l.mu.Lock()
	if !l.plist.Empty() {
		l.peerNotify(true)
	}
	l.mu.Unlock()

	return nil
}

func (l *leafState) peerNotify(nosig bool) {
	p := l.peer
	p.mu.Lock()
	defer p.mu.Unlock()

	if l.notified {
		return
	}

	p.llist.PushBack(&l.llist)
	l.notified = true

	if !nosig {
		select {
		case p.writerNotify <- struct{}{}:
		default:
		}
	}
}

func (p *peerState) peerWriter(ctx context.Context) {
	defer close(p.writerDone)

	for {
		select {
		case <-p.writerNotify:
			err := func() error {
				// handle leaf exiting msg
				for {
					var msg *protoMsg
					p.mu.Lock()
					if !p.elist.Empty() {
						msg = p.elist.PopFront().Value.(*protoMsg)
					}
					p.mu.Unlock()

					if msg == nil {
						break
					}
					// do write io
					if err := msg.writeTo(p.conn); err != nil {
						return err
					}
				}

				// handle notified leaves
				eventCnt := 0
				for {
					l := p.leafDequeue(ctx)
					if l == nil {
						ctxlog.Debugf(ctx, "peer writer has consumed all %v events", eventCnt)
						break
					}

					eventCnt++
					if err := p.leafConsume(ctx, l); err != nil {
						return err
					}
				}

				return nil
			}()
			if err != nil {
				ctxlog.Errorf(ctx, "peer writer exit with io error: %v", err)
				p.peerExit()
				return
			}
		case <-p.writerExit:
			ctxlog.Infof(ctx, "peer writer exit with p.writerExit")
			return
		} // select
	} // for
}

func (p *peerState) leafExitingInput(msg *protoMsg) {
	msg.sle.Value = msg
	p.mu.Lock()
	p.elist.PushBack(&msg.sle)
	p.mu.Unlock()
	select {
	case p.writerNotify <- struct{}{}:
	default:
	}
}

func (p *peerState) peerClose(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// set quiting flag
	p.quiting = true
	// notify all leaf to quit
	for _, l := range p.leafStates {
		l.leafExit()
	}
}

func (l *leafState) peerWriterInput(ctx context.Context, msg *protoMsg) {
	msg.sle.Value = msg

	l.mu.Lock()
	defer l.mu.Unlock()

	// enqueue msg
	l.plist.PushBack(&msg.sle)
	// update state
	l.fc.snt += uint32(len(msg.data))
	// notify peer writer
	l.peerNotify(false)
	// block on kFlowPause
	for l.fc.state() == kFlowPause && !l.exiting {
		ctxlog.Debugf(ctx, "leaf paused [snt:%v][ack:%v] [inflight:%v] > [window:%v]",
			l.fc.snt, l.fc.ack, l.fc.snt-l.fc.ack, l.fc.win)
		l.cond.Wait()
	}
}

func (l *leafState) leafExit() {
	l.readerExit <- struct{}{}

	ev := &protoMsg{cmd: 0}
	ev.sle.Value = ev
	l.writerMutex.Lock()
	l.writerInput.PushFront(&ev.sle)
	l.writerCond.Signal()
	l.writerMutex.Unlock()

	l.mu.Lock()
	l.exiting = true
	l.cond.Broadcast()
	l.mu.Unlock()
}

func (l *leafState) leafReader(ctx context.Context) {
	defer close(l.readerDone)

	ioInput, ioQuit := reader2chan(l.conn)
	defer close(ioQuit)
	for {
		select {
		case ev := <-ioInput:
			// eof
			if ev == nil {
				l.peerWriterInput(ctx, &protoMsg{cmd: kCmdEOF, cid: l.id})
				ctxlog.Infof(ctx, "leaf reader exit with EOF")
				return
			}
			// io error
			if err, ok := ev.(error); ok {
				ctxlog.Errorf(ctx, "leaf reader exit with error: %v", err)
				l.leafExit()
				l.peer.leafExitingInput(&protoMsg{cmd: kCmdClose, cid: l.id})
				return
			}

			data := ev.([]byte)
			if len(data) > kMsgRecvMaxLen {
				panic("ensure this")
			}

			// metric
			if l.metric.FirstRead == 0 {
				l.metric.FirstRead = time.Now().UnixNano() / 1000
			}
			l.metric.LastRead = time.Now().UnixNano() / 1000
			atomic.AddInt64(&l.metric.BytesRead, int64(len(data)))

			// send data to peer
			ctxlog.Debugf(ctx, "leaf reader got %v bytes", len(data))
			l.peerWriterInput(ctx, &protoMsg{cmd: kCmdData, cid: l.id, data: data})
		case <-l.readerExit:
			ctxlog.Infof(ctx, "leaf reader exit with l.readerExit")
			return
		} // select
	} // for
}

func (l *leafState) leafWriter(ctx context.Context) {
	defer close(l.writerDone)

	for {
		l.writerMutex.Lock()
		for l.writerInput.Empty() {
			l.writerCond.Wait()
		}
		ev := l.writerInput.PopFront().Value.(*protoMsg)
		l.writerMutex.Unlock()

		// do io
		var err error
		switch ev.cmd {
		case 0:
			ctxlog.Infof(ctx, "peer writer exit with l.writerExit")
			return
		case kCmdData:
			// metric
			if l.metric.FirstWrite == 0 {
				l.metric.FirstWrite = time.Now().UnixNano() / 1000
			}
			l.metric.LastWrite = time.Now().UnixNano() / 1000
			atomic.AddInt64(&l.metric.BytesWritten, int64(len(ev.data)))

			ctxlog.Debugf(ctx, "leaf writer got %v bytes", len(ev.data))
			_, err = l.conn.Write(ev.data)
		case kCmdEOF:
			err = l.conn.(interface{ CloseWrite() error }).CloseWrite() // assume tcp
		default:
			panic("bad msg cmd")
		}

		if err != nil {
			ctxlog.Errorf(ctx, "leaf writer exit with io error: %v", err)
			l.leafExit()
			l.peer.leafExitingInput(&protoMsg{cmd: kCmdClose, cid: l.id})
			return
		}

		if ev.cmd == kCmdEOF {
			ctxlog.Infof(ctx, "leaf writer exit with EOF")
			return
		}

		if len(ev.data) > 0 {
			needAck := false
			l.mu.Lock()
			// update t.rcv
			l.fc.rcv += uint32(len(ev.data))
			ack := l.fc.rcv
			// send empty data packet to ack peer
			if l.plist.Empty() {
				// NOTE: can't call t.peerWriterInput() since we can't block on here
				needAck = true
				msg := &protoMsg{cmd: kCmdData, cid: l.id, data: nil}
				msg.sle.Value = msg
				l.plist.PushBack(&msg.sle)
				l.peerNotify(false)
			}
			l.mu.Unlock()
			ctxlog.Debugf(ctx, "peer writer [need_ack:%v][ack:%v]", needAck, ack)
		}
	} // for
}

func (l *leafState) leafUpdateAck(ack uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if ack != l.fc.ack && ack-l.fc.ack < 1<<31 { // FIXME: 1<<30
		prevState := l.fc.state()
		l.fc.ack = ack
		if prevState == kFlowPause {
			l.cond.Signal()
		}
	}
}

func (l *leafState) leafClose(ctx context.Context) {
	// metric
	l.metric.Closed = time.Now().UnixNano() / 1000
	if metric, err := json.Marshal(l.metric); err == nil {
		ctxlog.Debugf(context.Background(), "METRIC %s", string(metric))
	}

	// erase from peer's leaf map
	l.peer.mu.Lock()
	defer l.peer.mu.Unlock()
	delete(l.peer.leafStates, l.id)
	atomic.AddInt64(&l.peer.pmetric.LeavesCloseCount, 1)

	if len(l.peer.leafStates) == 0 {
		ctxlog.Debugf(ctx, "i am the last leaf")
	}
}

func (p *peerState) getMetric() (pm peerMetric) {
	pm.BytesRead = atomic.LoadInt64(&p.pmetric.BytesRead)
	pm.BytesWritten = atomic.LoadInt64(&p.pmetric.BytesWritten)
	pm.LeavesCreateCount = atomic.LoadInt64(&p.pmetric.LeavesCreateCount)
	pm.LeavesCloseCount = atomic.LoadInt64(&p.pmetric.LeavesCloseCount)
	pm.Leaves = map[string]leafMetric{}

	p.mu.Lock()
	defer p.mu.Unlock()

	i := 0
	for _, l := range p.leafStates {
		if atomic.LoadInt64(&l.metric.Created) == 0 {
			continue
		}

		lm := leafMetric{}
		lm.Id = l.metric.Id
		lm.Leaf = l.metric.Leaf
		lm.Created = l.metric.Created
		lm.BytesRead = atomic.LoadInt64(&l.metric.BytesRead)
		lm.BytesWritten = atomic.LoadInt64(&l.metric.BytesWritten)
		pm.Leaves[lm.Leaf] = lm
		i++
	}

	return
}
