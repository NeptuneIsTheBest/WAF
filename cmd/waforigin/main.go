// Command waforigin is a loopback-only fixture for protocol and capacity tests.
package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/net/websocket"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "loopback test listener")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	ip, e := netip.ParseAddr(host)
	if err != nil || e != nil || !ip.IsLoopback() {
		fmt.Fprintln(os.Stderr, "fixture must bind a loopback IP")
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			fmt.Fprintf(w, "data: %d\n\n", time.Now().UnixNano())
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-t.C:
			}
		}
	})
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) { defer ws.Close(); io.Copy(ws, ws) }))
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).EnableFullDuplex()
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, "upload failed", 400)
			return
		}
		fmt.Fprintf(w, "received %d", n)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 16<<20)); err != nil {
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "origin ok "+strings.Repeat("x", 1014))
	})
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
