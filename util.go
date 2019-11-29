package ssloff

import _ "net/http/pprof"
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
