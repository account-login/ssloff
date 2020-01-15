package ssloff

import (
	"bufio"
	"bytes"
	"context"
	"github.com/pkg/errors"
	"gopkg.in/account-login/ctxlog.v2"
	"io"
	"net/url"
)

// TODO: limit http req size (ReadBytes)

func httpProxyHandshake(
// in
	ctx context.Context, reader *bufio.Reader, writer io.Writer) (
// out
	dstAddr socksAddr, dstPort uint16, peekData []byte, err error) {
	// body

	// split request line: GET http://google.com/ HTTP/1.1
	reqline, err := reader.ReadBytes('\n')
	if err != nil {
		err = errors.Wrap(err, "read http request line")
		return
	}
	s1 := bytes.IndexByte(reqline, ' ')
	s2 := bytes.LastIndexByte(reqline, ' ')

	httpSig := false
	for _, pattern := range [2][]byte{[]byte("HTTP/1.1"), []byte("HTTP/1.0")} {
		if bytes.HasPrefix(reqline[s2+1:], pattern) {
			httpSig = true
			break
		}
	}

	if !bytes.HasSuffix(reqline, []byte("\r\n")) || s1 <= 0 || s2 < 0 || !httpSig {
		err = errors.Errorf("bad http req: %s", reqline)
		return
	}
	method := reqline[:s1]
	rawUri := reqline[s1+1 : s2]

	// parse uri
	var uri *url.URL
	if bytes.Equal(method, []byte("CONNECT")) {
		// NOTE: can not url.ParseRequestURI() on "CONNECT host:443 HTTP/1.1"
		uri = &url.URL{Host: string(rawUri)}
	} else {
		uri, err = url.ParseRequestURI(string(rawUri))
		if err != nil {
			err = errors.Wrapf(err, "url.ParseRequestURI")
			return
		}
	}
	switch uri.Scheme {
	case "", "http", "https":
	default:
		err = errors.Errorf("Unknown uri scheme: %s", uri.Scheme)
		return
	}

	// read headers
	var headers [][]byte
	for {
		var line []byte
		line, err = reader.ReadBytes('\n')
		if err != nil {
			err = errors.Wrap(err, "read http header line")
			return
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			err = errors.Errorf("bad header line: %s", line)
			return
		}

		if len(line) == 2 {
			break
		}
		headers = append(headers, line)
	}

	// get dst addr from uri
	hostStr := ""
	if uri.Host != "" {
		hostStr = uri.Host
		dstAddr.atype = kSocksAddrDomain
		if host, port, terr := SplitHostPort(uri.Host); terr == nil {
			dstAddr.addr = []byte(host)
			dstPort = port
		} else {
			dstAddr.addr = []byte(uri.Host)
			dstPort = 80
			if uri.Scheme == "https" {
				dstPort = 443
			}
		}
	}

	// get dst addr from Host header
	if dstAddr.atype == 0 {
		for _, header := range headers {
			if bytes.HasPrefix(header, []byte("Host: ")) {
				dstAddr.atype = kSocksAddrDomain
				hostVal := header[len("Host: ") : len(header)-2]
				hostStr = string(hostVal)
				if host, port, terr := SplitHostPort(string(hostVal)); terr == nil {
					dstAddr.addr = []byte(host)
					dstPort = port
				} else {
					dstAddr.addr = hostVal
					dstPort = 80
				}

				break
			}
		}
	}
	if dstAddr.atype == 0 {
		err = errors.New("no dst addr")
		return
	}

	if bytes.Equal(method, []byte("CONNECT")) {
		// https connect proxy, send response
		ctxlog.Infof(ctx, "http connect [host:%s]", hostStr)

		_, err = writer.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		if err != nil {
			err = errors.Wrapf(err, "write response")
			return
		}

		peekData = bufioReaderRemains(reader)
	} else {
		// http proxy, rewrite req
		ctxlog.Infof(ctx, "http proxy [method:%s][host:%s][url:%s]",
			method, hostStr, rawUri)

		pieces := [][]byte{reqline[:s1+1], []byte(uri.RequestURI()), reqline[s2:]}
		for _, header := range headers {
			// remove Proxy-Connection, Proxy-Authorization, Proxy-Authenticate
			if !bytes.HasPrefix(header, []byte("Proxy-")) {
				pieces = append(pieces, header)
			}
		}
		pieces = append(pieces, []byte("\r\n"), bufioReaderRemains(reader))
		peekData = bytes.Join(pieces, nil)
	}
	return
}
