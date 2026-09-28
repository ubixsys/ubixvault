package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"sync/atomic"
	"time"
)

// handshakeAbortLog filters the http.Server error log. Load balancers and
// ingress controllers health-check backends with bare TCP connects; against a
// TLS listener each one aborts the handshake, and net/http logs a line for it.
// On a normal cluster that is one line per probe, per replica, forever — enough
// to bury everything else in the log.
//
// Only the abort class is held back: the peer closed or reset the connection
// before a handshake (or an HTTP/2 preface) completed. Those lines are counted
// and reported as a periodic summary instead. Every other server error — a
// failed certificate, an unsupported TLS version, a panic in a handler — is
// written through unchanged.
type handshakeAbortLog struct {
	out        io.Writer
	suppressed atomic.Uint64
}

func newHandshakeAbortLog(out io.Writer) *handshakeAbortLog {
	return &handshakeAbortLog{out: out}
}

// Logger returns a *log.Logger for http.Server.ErrorLog.
func (l *handshakeAbortLog) Logger() *log.Logger {
	return log.New(l, "", log.LstdFlags)
}

func (l *handshakeAbortLog) Write(p []byte) (int, error) {
	if isHandshakeAbort(p) {
		l.suppressed.Add(1)
		return len(p), nil
	}
	return l.out.Write(p)
}

// Run logs how many aborts were held back, once per interval and only when
// there were any, until ctx is done.
func (l *handshakeAbortLog) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := l.suppressed.Swap(0); n > 0 {
				log.Printf("%d aborted TLS handshakes in the last %s (connections closed before completing TLS, e.g. TCP health checks; -log-tls-handshake-aborts logs each)", n, every)
			}
		}
	}
}

var (
	tlsHandshakeError = []byte("http: TLS handshake error from ")
	http2PrefaceError = []byte("http2: server: error reading preface from client ")
	abortCauses       = [][]byte{
		[]byte(": EOF\n"),
		[]byte("connection reset by peer"),
		[]byte("broken pipe"),
	}
)

// isHandshakeAbort reports whether a server log line is a TLS handshake or
// HTTP/2 preface that failed only because the peer went away.
func isHandshakeAbort(line []byte) bool {
	if !bytes.Contains(line, tlsHandshakeError) && !bytes.Contains(line, http2PrefaceError) {
		return false
	}
	for _, cause := range abortCauses {
		if bytes.Contains(line, cause) {
			return true
		}
	}
	return false
}
