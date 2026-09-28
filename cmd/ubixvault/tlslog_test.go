package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIsHandshakeAbort(t *testing.T) {
	cases := map[string]bool{
		// Lines from a live cluster: TCP health checks against the TLS port.
		"2026/09/28 23:04:14 http: TLS handshake error from 10.42.7.127:48550: write tcp 10.42.5.143:8200->10.42.7.127:48550: write: connection reset by peer\n":               true,
		"2026/09/28 23:04:15 http2: server: error reading preface from client 10.42.5.65:36228: read tcp 10.42.5.143:8200->10.42.5.65:36228: read: connection reset by peer\n": true,
		"2026/09/28 23:04:16 http: TLS handshake error from 10.42.7.127:48551: EOF\n":                                                                                          true,
		"2026/09/28 23:04:17 http: TLS handshake error from 10.42.7.127:48552: write tcp 10.42.5.143:8200->10.42.7.127:48552: write: broken pipe\n":                            true,

		// Real handshake failures an operator needs to see.
		"2026/09/28 23:04:18 http: TLS handshake error from 10.0.0.9:5000: tls: client offered only unsupported versions: [301]\n": false,
		"2026/09/28 23:04:19 http: TLS handshake error from 10.0.0.9:5001: remote error: tls: bad certificate\n":                   false,
		"2026/09/28 23:04:20 http: TLS handshake error from 10.0.0.9:5002: EOF while reading something\n":                          false,

		// Anything else net/http logs is untouched, even if it mentions a reset.
		"2026/09/28 23:04:21 http: panic serving 10.0.0.9:5003: connection reset by peer\n": false,
		"2026/09/28 23:04:22 http: Accept error: accept tcp: too many open files\n":         false,
	}
	for line, want := range cases {
		if got := isHandshakeAbort([]byte(line)); got != want {
			t.Errorf("isHandshakeAbort(%q) = %v, want %v", line, got, want)
		}
	}
}

// syncBuffer is a bytes.Buffer safe for the server's logging goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestHandshakeAbortLogAgainstTLSServer drives a real TLS server, so the test
// fails if net/http changes the wording of the lines being filtered.
func TestHandshakeAbortLogAgainstTLSServer(t *testing.T) {
	var out syncBuffer
	filter := newHandshakeAbortLog(&out)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = filter.Logger()
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	// A TCP health check: connect, then close without speaking TLS.
	const probes = 3
	for range probes {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}

	// A genuine failure: a client speaking plain HTTP to the TLS port.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_, _ = conn.Read(make([]byte, 512))
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for filter.suppressed.Load() < probes || !strings.Contains(out.String(), "TLS handshake error") {
		if time.Now().After(deadline) {
			t.Fatalf("suppressed = %d, want %d; log = %q", filter.suppressed.Load(), probes, out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	logged := out.String()
	if strings.Count(logged, "\n") != 1 || !strings.Contains(logged, "HTTP request to an HTTPS server") {
		t.Errorf("want exactly the plain-HTTP failure logged, got %q", logged)
	}
}
