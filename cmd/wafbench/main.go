// Command wafbench generates isolated benchmark policies and measures HTTP/SSE/WS workloads.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
	"waf/internal/config"
)

type results struct {
	mu                                                                             sync.Mutex
	Scheduled, Completed, Errors, Cancelled, Overload, Bytes, Opened, Peak, active int64
	Status                                                                         map[int]int64
	LatencyMS                                                                      []float64
	seen                                                                           int64
}

func (r *results) record(status int, n int64, d time.Duration, err error, cancelled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Completed++
	r.Bytes += n
	if err != nil {
		if cancelled {
			r.Cancelled++
		} else {
			r.Errors++
		}
	}
	if status != 0 {
		r.Status[status]++
	}
	if status != 0 {
		r.seen++
		value := float64(d.Microseconds()) / 1000
		if len(r.LatencyMS) < 100000 {
			r.LatencyMS = append(r.LatencyMS, value)
		} else if index := rand.Int64N(r.seen); index < 100000 {
			r.LatencyMS[index] = value
		}
	}
}
func (r *results) open() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Opened++
	r.active++
	r.Peak = max(r.Peak, r.active)
}
func (r *results) close() { r.mu.Lock(); r.active--; r.mu.Unlock() }
func main() {
	mode := flag.String("mode", "http", "http, sse or websocket")
	base := flag.String("url", "http://127.0.0.1:18080", "WAF address (path selected by mode)")
	pattern := flag.String("host-pattern", "bench-%02d.localhost", "Host header pattern, one integer argument")
	sites := flag.Int("sites", 50, "number of configured hosts")
	rps := flag.Int("rps", 1000, "HTTP requests per second")
	workers := flag.Int("workers", 100, "HTTP concurrent workers")
	connections := flag.Int("connections", 1000, "long connection count")
	duration := flag.Duration("duration", time.Minute, "measurement duration")
	ramp := flag.Duration("ramp", 30*time.Second, "long connection ramp time")
	insecure := flag.Bool("insecure", false, "explicitly trust a local test TLS certificate")
	serverName := flag.String("server-name", "", "TLS SNI name; defaults to first host")
	configOut := flag.String("config-out", "", "write a benchmark configuration bundle instead of sending traffic")
	upstream := flag.String("upstream", "http://127.0.0.1:18081", "fixture origin for generated configuration")
	flag.Parse()
	if (*mode == "sse" || *mode == "websocket") && *ramp >= *duration {
		fmt.Fprintln(os.Stderr, "connection ramp must finish before measurement ends")
		os.Exit(1)
	}
	if *sites < 1 || *sites > 200 || *rps < 1 || *rps > 100000 || *workers < 1 || *workers > 8192 || *connections < 1 || *connections > 8192 || *duration <= 0 || *ramp < 0 {
		fmt.Fprintln(os.Stderr, "invalid benchmark limits")
		os.Exit(1)
	}
	hosts := make([]string, *sites)
	for i := range hosts {
		hosts[i] = fmt.Sprintf(*pattern, i+1)
		if !config.ValidDomain(hosts[i], false) {
			fmt.Fprintln(os.Stderr, "invalid host pattern")
			os.Exit(1)
		}
	}
	if *configOut != "" {
		bundle := config.Bundle{Sites: []config.Site{}}
		for i, host := range hosts {
			s := config.DefaultSite()
			s.ID = fmt.Sprintf("bench-%02d", i+1)
			s.Name = s.ID
			s.Domains = []string{host}
			s.HTTPS = false
			s.RedirectHTTP = false
			s.Upstreams = []config.Upstream{{URL: *upstream, Weight: 1}}
			s.Managed.Mode = "block"
			for j := 0; j < 10; j++ {
				s.Rules = append(s.Rules, config.CustomRule{ID: fmt.Sprintf("rule-%d", j), Name: "benchmark predicate", Enabled: true, Priority: j, Expression: fmt.Sprintf(`request.path.startsWith("/blocked-%d")`, j), Action: "block"})
			}
			bundle.Sites = append(bundle.Sites, s)
		}
		raw, _ := json.MarshalIndent(bundle, "", "  ")
		if err := os.WriteFile(*configOut, append(raw, '\n'), 0600); err != nil {
			panic(err)
		}
		return
	}
	u, err := url.Parse(*base)
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "invalid URL")
		os.Exit(1)
	}
	if *serverName == "" {
		*serverName = hosts[0]
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: *serverName, InsecureSkipVerify: *insecure}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	transport.ForceAttemptHTTP2 = true
	transport.MaxConnsPerHost = 8192
	transport.MaxIdleConns = 8192
	transport.MaxIdleConnsPerHost = 8192
	transport.DisableCompression = true
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	stats := &results{Status: map[int]int64{}}
	start := time.Now()
	var wg sync.WaitGroup
	switch *mode {
	case "http":
		jobs := make(chan int, *workers)
		for i := 0; i < *workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					payload := []byte(`{"message":"` + strings.Repeat("a", 1010) + `"}`)
					req, _ := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(payload))
					req.Host = hosts[job%len(hosts)]
					req.Header.Set("Content-Type", "application/json")
					at := time.Now()
					resp, err := client.Do(req)
					var n int64
					status := 0
					if err == nil {
						status = resp.StatusCode
						n, err = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						if err == nil && (status < 200 || status >= 300) {
							err = fmt.Errorf("HTTP status %d", status)
						}
					}
					stats.record(status, n, time.Since(at), err, ctx.Err() != nil)
				}
			}()
		}
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		sent := 0
	run:
		for {
			select {
			case <-ctx.Done():
				break run
			case <-ticker.C:
				target := int(time.Since(start).Seconds() * float64(*rps))
				for sent < target {
					stats.Scheduled++
					select {
					case jobs <- sent:
					default:
						stats.Overload++
					}
					sent++
				}
			}
		}
		close(jobs)
	case "sse", "websocket":
		for i := 0; i < *connections; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				delay := time.NewTimer(time.Duration(i) * (*ramp) / time.Duration(*connections))
				defer delay.Stop()
				select {
				case <-ctx.Done():
					return
				case <-delay.C:
				}
				host := hosts[i%len(hosts)]
				if *mode == "sse" {
					target := *u
					target.Path = "/events"
					req, _ := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
					req.Host = host
					req.Header.Set("Accept", "text/event-stream")
					at := time.Now()
					resp, err := client.Do(req)
					if err != nil {
						stats.record(0, 0, time.Since(at), err, ctx.Err() != nil)
						return
					}
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						stats.record(resp.StatusCode, 0, time.Since(at), fmt.Errorf("stream status %d", resp.StatusCode), false)
						return
					}
					stats.open()
					defer stats.close()
					n, err := io.Copy(io.Discard, resp.Body)
					if err == nil && ctx.Err() == nil {
						err = fmt.Errorf("stream ended before measurement finished")
					}
					stats.record(resp.StatusCode, n, time.Since(at), err, ctx.Err() != nil)
					return
				}
				address := u.Host
				if u.Port() == "" {
					port := "80"
					if u.Scheme == "https" {
						port = "443"
					}
					address = net.JoinHostPort(u.Hostname(), port)
				}
				conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
				at := time.Now()
				if err != nil {
					stats.record(0, 0, 0, err, ctx.Err() != nil)
					return
				}
				defer conn.Close()
				rawConn := conn
				stop := context.AfterFunc(ctx, func() { rawConn.Close() })
				defer stop()
				if u.Scheme == "https" {
					tc := tls.Client(conn, tlsConfig.Clone())
					if err = tc.HandshakeContext(ctx); err != nil {
						stats.record(0, 0, time.Since(at), err, ctx.Err() != nil)
						return
					}
					conn = tc
				}
				scheme := "ws"
				origin := "http://" + host
				if u.Scheme == "https" {
					scheme = "wss"
					origin = "https://" + host
				}
				cfg, _ := websocket.NewConfig(scheme+"://"+host+"/ws", origin)
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				ws, err := websocket.NewClient(cfg, conn)
				if err != nil {
					stats.record(0, 0, time.Since(at), err, ctx.Err() != nil)
					return
				}
				defer ws.Close()
				conn.SetDeadline(time.Time{})
				stats.open()
				defer stats.close()
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				var n int64
				for {
					ws.SetDeadline(time.Now().Add(5 * time.Second))
					err = websocket.Message.Send(ws, "ping")
					if err == nil {
						var reply string
						err = websocket.Message.Receive(ws, &reply)
						n += int64(len(reply))
					}
					if err != nil {
						stats.record(101, n, time.Since(at), err, ctx.Err() != nil)
						return
					}
					select {
					case <-ctx.Done():
						stats.record(101, n, time.Since(at), nil, false)
						return
					case <-ticker.C:
					}
				}
			}(i)
		}
	default:
		fmt.Fprintln(os.Stderr, "invalid mode")
		os.Exit(1)
	}
	wg.Wait()
	elapsed := time.Since(start)
	sort.Float64s(stats.LatencyMS)
	percentile := func(p float64) float64 {
		if len(stats.LatencyMS) == 0 {
			return 0
		}
		return stats.LatencyMS[min(len(stats.LatencyMS)-1, int(float64(len(stats.LatencyMS)-1)*p))]
	}
	result := map[string]any{"mode": *mode, "duration_seconds": elapsed.Seconds(), "sites": *sites, "scheduled": stats.Scheduled, "completed": stats.Completed, "errors": stats.Errors, "cancelled_at_stop": stats.Cancelled, "generator_overload": stats.Overload, "completed_per_second": float64(stats.Completed) / elapsed.Seconds(), "bytes": stats.Bytes, "status": stats.Status, "latency_p50_ms": percentile(.50), "latency_p95_ms": percentile(.95), "latency_p99_ms": percentile(.99), "latency_sample_count": len(stats.LatencyMS), "connections_opened": stats.Opened, "peak_connections": stats.Peak}
	result["latency_measure"] = "request_duration"
	if *mode != "http" {
		result["latency_measure"] = "connection_lifetime"
	}
	json.NewEncoder(os.Stdout).Encode(result)
	if stats.Errors > 0 || stats.Overload > 0 || *mode != "http" && stats.Peak != int64(*connections) {
		os.Exit(1)
	}
}
