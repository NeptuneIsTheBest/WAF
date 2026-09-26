package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"waf/internal/admin"
	"waf/internal/config"
	"waf/internal/proxy"
	"waf/internal/store"
	"waf/internal/tlsmgr"
)

type Connections struct {
	mu          sync.Mutex
	connections map[*trackedConn]bool
	max         int
}
type trackedConn struct {
	net.Conn
	owner *Connections
	once  sync.Once
}

func (c *trackedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.connections, c); c.owner.mu.Unlock() })
	return e
}
func (c *Connections) CloseAll() {
	c.mu.Lock()
	all := make([]*trackedConn, 0, len(c.connections))
	for conn := range c.connections {
		all = append(all, conn)
	}
	c.mu.Unlock()
	for _, conn := range all {
		conn.Close()
	}
}
func (c *Connections) Count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.connections) }

type listener struct {
	net.Listener
	connections *Connections
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		l.connections.mu.Lock()
		if len(l.connections.connections) >= l.connections.max {
			l.connections.mu.Unlock()
			conn.Close()
			continue
		}
		tracked := &trackedConn{Conn: conn, owner: l.connections}
		l.connections.connections[tracked] = true
		l.connections.mu.Unlock()
		return tracked, nil
	}
}

func Run(ctx context.Context, boot config.Bootstrap) error {
	if err := cleanBodyFiles(boot.DataDir); err != nil {
		return err
	}
	s, err := store.Open(boot)
	if err != nil {
		return err
	}
	defer s.Close()
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	e := proxy.New(boot, s.Key(), s, reg)
	defer e.Close()
	rev, err := s.Active()
	if err != nil {
		return err
	}
	snapshot, err := e.Compile(rev.Bundle)
	if err != nil {
		return err
	}
	e.Activate(snapshot, rev.ID)
	certs := tlsmgr.New(boot, s)
	defer certs.Close()
	if err = certs.Validate(snapshot.Bundle); err != nil {
		return err
	}
	console := admin.New(boot, s, e, certs)
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.Host(r.Host) == boot.AdminDomain {
			if r.TLS == nil && !boot.Development {
				http.Redirect(w, r, "https://"+boot.AdminDomain+r.URL.RequestURI(), 308)
				return
			}
			console.ServeHTTP(w, r)
			return
		}
		e.ServeHTTP(w, r)
	})
	connections := &Connections{connections: map[*trackedConn]bool{}, max: boot.MaxConnections}
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "waf_connections", Help: "Open TCP connections including WebSockets."}, func() float64 { return float64(connections.Count()) }), prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "waf_log_dropped_total", Help: "Events dropped because the queue or storage was unavailable."}, func() float64 { return float64(s.Dropped.Load()) }), prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "waf_log_write_errors_total", Help: "Event storage write errors."}, func() float64 { return float64(s.WriteErrors.Load()) }), prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "waf_certificate_min_remaining_seconds", Help: "Minimum certificate lifetime; zero when a configured production certificate is missing."}, func() float64 {
		minimum := 365 * 24 * time.Hour
		for _, status := range certs.Statuses() {
			expiry, err := time.Parse(time.RFC3339, status.Expires)
			if err != nil {
				return 0
			}
			if left := time.Until(expiry); left < minimum {
				minimum = left
			}
		}
		return minimum.Seconds()
	}))
	type running struct {
		server   *http.Server
		listener net.Listener
		tls      bool
	}
	servers := []running{}
	closeListeners := func() {
		for _, s := range servers {
			s.listener.Close()
		}
	}
	defer closeListeners()
	for _, entry := range []struct {
		address string
		tls     bool
	}{{boot.HTTPListen, false}, {boot.HTTPSListen, true}} {
		if entry.address == "" {
			continue
		}
		ln, err := net.Listen("tcp", entry.address)
		if err != nil {
			return err
		}
		server := &http.Server{Handler: router, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: certs.TLSConfig(), HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 128, MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 256 << 10, SendPingTimeout: 60 * time.Second, PingTimeout: 15 * time.Second, WriteByteTimeout: 30 * time.Second}}
		servers = append(servers, running{server, &listener{Listener: ln, connections: connections}, entry.tls})
	}
	if boot.OpsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{MaxRequestsInFlight: 2, Timeout: 5 * time.Second}))
		mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
		mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			if !certs.Ready() || !e.Ready() {
				http.Error(w, "certificate not ready", 503)
				return
			}
			fmt.Fprintln(w, "ok")
		})
		ln, err := net.Listen("tcp", boot.OpsListen)
		if err != nil {
			return err
		}
		servers = append(servers, running{&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}, ln, false})
	}
	if err = certs.Sync(snapshot.Bundle); err != nil {
		return err
	}
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s running) {
			var err error
			if s.tls {
				err = s.server.ServeTLS(s.listener, "", "")
			} else {
				err = s.server.Serve(s.listener)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			} else {
				errCh <- nil
			}
		}(s)
	}
	slog.Info("WAF started", "http", boot.HTTPListen, "https", boot.HTTPSListen, "admin_domain", boot.AdminDomain, "revision", rev.ID, "development", boot.Development)
	select {
	case <-ctx.Done():
	case err = <-errCh:
		if err == nil {
			err = errors.New("listener stopped unexpectedly")
		}
	}
	e.BeginDrain()
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(server *http.Server) { defer wg.Done(); server.Shutdown(shutdown) }(s.server)
	}
	wg.Wait()
	for connections.Count() > 0 && shutdown.Err() == nil {
		select {
		case <-shutdown.Done():
		case <-time.After(25 * time.Millisecond):
		}
	}
	connections.CloseAll()
	for _, s := range servers {
		s.server.Close()
	}
	settle, settleCancel := context.WithTimeout(context.Background(), 5*time.Second)
	e.Wait(settle)
	settleCancel()
	slog.Info("WAF stopped")
	return err
}
