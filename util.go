package ssloff

import (
	"bufio"
	"github.com/pkg/errors"
	"net"
	_ "net/http/pprof"
	"strconv"
)
import (
	"context"
	"gopkg.in/account-login/ctxlog.v2"
	"io"
	"net/http"
)

type readerWriter struct {
	io.Reader
	io.Writer
}

func safeClose(ctx context.Context, closer io.Closer) {
	if err := closer.Close(); err != nil {
		ctxlog.Errorf(ctx, "close: %v", err)
	}
}

// return one of data, nil, error
func reader2chan(reader io.Reader) (result chan interface{}, quit chan struct{}) {
	result = make(chan interface{}, 2)
	quit = make(chan struct{})

	go func() {
		buf := make([]byte, kReaderBuf)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case <-quit:
					return
				case result <- data:
				}
			}

			if err != nil {
				var sig interface{} = err
				if err == io.EOF {
					sig = nil
				}
				select {
				case <-quit:
				case result <- sig:
				}
				return
			}
		}
	}()

	return
}

func SplitHostPort(hostPort string) (host string, port uint16, err error) {
	var portStr string
	var portInt uint64
	host, portStr, err = net.SplitHostPort(hostPort)
	if err != nil {
		return
	}

	portInt, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		err = errors.Wrapf(err, "SplitHostPort: can not parse port: %q", portStr)
		return
	}
	port = uint16(portInt)
	return
}

func bufioReaderRemains(reader *bufio.Reader) []byte {
	peekData, err := reader.Peek(reader.Buffered())
	if err != nil {
		panic(err)
	}
	return peekData
}

func StartDebugServer(ctx context.Context, addr string) (server *http.Server) {
	server = &http.Server{Addr: addr, Handler: nil}
	go func() {
		dbgServerStart()

		err := server.ListenAndServe()
		if err != nil {
			ctxlog.Errorf(ctx, "StartDebugServer: %v", err)
			return
		}
	}()
	return
}
