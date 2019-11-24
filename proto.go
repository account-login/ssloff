package ssloff

import (
	"encoding/binary"
	"fmt"
	"io"
)

// len  cmd  cid  ack  xxxx
// .... .... .... ....

type protoMsg struct {
	cmd  uint32
	cid  uint32
	ack  uint32
	data []byte
	// only used by protoParser
	err error
	// quene
	sle SLElement
}

func (msg *protoMsg) writeTo(w io.Writer) error {
	if msg.err != nil {
		panic("???")
	}

	var h [4 * 4]byte
	binary.LittleEndian.PutUint32(h[0:4], uint32(len(msg.data)))
	binary.LittleEndian.PutUint32(h[4:8], msg.cmd)
	binary.LittleEndian.PutUint32(h[8:12], msg.cid)
	binary.LittleEndian.PutUint32(h[12:16], msg.ack)
	_, err := w.Write(h[:])
	if err != nil {
		return err
	}

	_, err = w.Write(msg.data)
	return err
}

func protoParser(reader io.Reader) (result chan *protoMsg, quit chan struct{}) {
	result = make(chan *protoMsg, kChannelSize)
	quit = make(chan struct{})

	go func() {
		var err error

		for {
			var h [4 * 4]byte
			_, err = io.ReadFull(reader, h[:])
			if err != nil {
				break
			}

			msgLen := binary.LittleEndian.Uint32(h[0:4])
			if msgLen > kMsgRecvMaxLen {
				err = fmt.Errorf("received msg [len:%v] > [limit:%v]", msgLen, kMsgRecvMaxLen)
				break
			}

			data := make([]byte, msgLen)
			_, err = io.ReadFull(reader, data)
			if err != nil {
				break
			}

			msg := &protoMsg{
				cmd:  binary.LittleEndian.Uint32(h[4:8]),
				cid:  binary.LittleEndian.Uint32(h[8:12]),
				ack:  binary.LittleEndian.Uint32(h[12:16]),
				data: data,
			}

			select {
			case result <- msg:
			case <-quit:
				return
			}
		} // for

		// EOF or other error
		select {
		case result <- &protoMsg{err: err}:
		case <-quit:
		}
	}()

	return
}
