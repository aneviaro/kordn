package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kordn-ai/kordn/internal/pki"
)

func writeConnectEstablished(conn net.Conn) error {
	_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: kordn\r\n\r\n")
	return err
}

func tunnel(ctx context.Context, client net.Conn, clientReader *bufio.Reader, upstream net.Conn, limits Limits) {
	if client == nil || upstream == nil {
		return
	}
	defer client.Close()
	defer upstream.Close()
	if clientReader == nil {
		clientReader = bufio.NewReader(client)
	}
	bufferedClient := &bufferedConn{Conn: client, reader: clientReader}
	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, bufferedClient)
		closeWrite(upstream)
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
		copyDone <- struct{}{}
	}()

	// Preserve half-close semantics: one finished direction should not discard
	// a response still being written in the other direction. Context
	// cancellation and an idle peer, however, must close both sockets so the
	// copier goroutines cannot outlive the request indefinitely.
	select {
	case <-copyDone:
	case <-ctxDone(ctx):
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	idle := limits.IdleTimeout
	if idle <= 0 {
		idle = DefaultLimits().IdleTimeout
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()
	select {
	case <-copyDone:
		return
	case <-ctxDone(ctx):
		_ = client.Close()
		_ = upstream.Close()
	case <-timer.C:
		_ = client.Close()
		_ = upstream.Close()
	}
}

func ctxDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

func closeWrite(conn net.Conn) {
	if writer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type oneConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	return nil, errors.New("single connection listener is closed")
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func serveInterceptedTLS(client net.Conn, clientReader *bufio.Reader, server *Server, dest destination) {
	if server != nil {
		defer server.untrackConn(client)
	}
	if server == nil || server.leaves == nil || server.ca == nil {
		_ = client.Close()
		return
	}
	leaf, err := server.leaves.Get(dest.Host)
	if err != nil {
		_ = client.Close()
		return
	}
	tlsConn := tls.Server(&bufferedConn{Conn: client, reader: clientReader}, pki.TLSConfig(leaf))
	ctx, cancel := context.WithTimeout(context.Background(), server.limits.ConnectTimeout)
	err = tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		server.handleIntercepted(w, req, dest)
	})
	httpServer := &http.Server{
		Handler:           inner,
		ReadHeaderTimeout: server.limits.ReadHeaderTimeout,
		ReadTimeout:       server.limits.ReadTimeout,
		WriteTimeout:      server.limits.WriteTimeout,
		IdleTimeout:       server.limits.IdleTimeout,
		MaxHeaderBytes:    server.limits.MaxHeaderBytes,
	}
	_ = httpServer.Serve(&oneConnListener{conn: tlsConn})
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range stringsSplitComma(value) {
			header.Del(name)
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func stringsSplitComma(value string) []string {
	result := make([]string, 0, 4)
	for _, part := range splitComma(value) {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func splitComma(value string) []string {
	result := make([]string, 0, 4)
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func destinationURL(dest destination) string {
	return dest.Host + ":" + strconv.Itoa(dest.Port)
}
