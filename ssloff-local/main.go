package main

import (
	"context"
	"flag"
	"github.com/account-login/ssloff"
	"gopkg.in/account-login/ctxlog.v2"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// logging
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	// ctx
	ctx := context.Background()

	// args
	mitm := ssloff.MITM{}
	local := ssloff.Local{}
	flag.StringVar(&local.LocalAddr, "local", "127.0.0.1:1180",
		"listen on this address")
	flag.StringVar(&local.RemoteAddr, "remote", "127.0.0.1:2180",
		"connect to remote")
	flag.Float64Var(&local.DialTimeout, "dial-timeout", 2.0,
		"dial timeout to remote")
	flag.Float64Var(&local.HandshakeTimeout, "handshake-timeout", 2.0,
		"handshake timeout from client (socks handshake or https proxy req)")
	noMITM := flag.Bool("no-mitm", false, "disable MITM")
	flag.StringVar(&mitm.CAPath, "ca", "ca.pem", "path to CA")
	flag.StringVar(&mitm.CacheDir, "cert-dir", "", "path to cert cache")
	debugServerPtr := flag.String("debug", "", "debug server addr")
	logfile := flag.String("log", "", "log file")
	flag.Parse()

	if *logfile != "" {
		f, err := os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}

	if !*noMITM {
		if err := mitm.Init(); err != nil {
			ctxlog.Fatal(ctx, err)
			return
		}
		local.MITM = &mitm
	}

	if *debugServerPtr != "" {
		_ = ssloff.StartDebugServer(ctx, *debugServerPtr)
	}

	// start local
	if err := local.Start(ctx); err != nil {
		ctxlog.Fatal(ctx, err)
		return
	}
	ctxlog.Infof(ctx, "listening on %v, remote is %v", local.LocalAddr, local.RemoteAddr)

	// exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	ctxlog.Infof(ctx, "exiting")
}
