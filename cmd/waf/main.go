package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"waf/internal/app"
	"waf/internal/backup"
	"waf/internal/config"
	"waf/internal/policy"
	"waf/internal/proxy"
	"waf/internal/secure"
	"waf/internal/store"
	"waf/internal/tlsmgr"
)

var version = "dev"
var commit = "unknown"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "waf:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	command := args[0]
	if command == "version" {
		fmt.Printf("waf %s (%s), OWASP CRS %s\n", version, commit, policy.CRSVersion)
		return nil
	}
	if command == "init" {
		return initialize(args[1:])
	}
	if command == "help" || command == "--help" || command == "-h" {
		usage()
		return nil
	}
	if command != "serve" && command != "check" && command != "doctor" && command != "backup" && command != "restore" && command != "reset-admin" {
		return errors.New("unknown command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	cfgPath := flags.String("config", "/etc/waf/waf.json", "bootstrap configuration file")
	out := flags.String("out", "", "backup output file")
	input := flags.String("in", "", "encrypted backup input file")
	passwordFile := flags.String("password-file", "", "read password from a protected file instead of the terminal")
	username := flags.String("username", "admin", "administrator username")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	boot, e := config.Load(*cfgPath)
	if e != nil {
		return e
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		boot.MasterKeyFile = filepath.Join(dir, "master.key")
	}
	if command == "doctor" {
		return doctor(boot)
	}
	unlock, e := app.Lock(boot.DataDir)
	if e != nil {
		return e
	}
	defer unlock()
	if command == "serve" {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return app.Run(ctx, boot)
	}
	if command == "restore" {
		if *input == "" {
			return errors.New("--in is required")
		}
		password, e := readSecret(*passwordFile, "Backup password: ")
		if e != nil {
			return e
		}
		f, e := os.Open(*input)
		if e != nil {
			return e
		}
		defer f.Close()
		dir, e := backup.Extract(boot, password, f)
		if e != nil {
			return e
		}
		defer os.RemoveAll(dir)
		checkBoot := boot
		checkBoot.DataDir = dir
		s, e := store.Open(checkBoot)
		if e != nil {
			return e
		}
		if e = s.Check(context.Background()); e != nil {
			s.Close()
			return e
		}
		rev, e := s.Active()
		if e != nil {
			s.Close()
			return e
		}
		engine := proxy.New(checkBoot, s.Key(), s, nil)
		snapshot, e := engine.Compile(rev.Bundle)
		if e != nil {
			s.Close()
			return e
		}
		snapshot.Release()
		s.Close()
		saved := boot.DataDir + ".pre-restore-" + time.Now().UTC().Format("20060102T150405")
		if e = os.Rename(boot.DataDir, saved); e != nil {
			return e
		}
		if e = os.Rename(dir, boot.DataDir); e != nil {
			os.Rename(saved, boot.DataDir)
			return e
		}
		fmt.Println("Restored. Previous data retained at", saved)
		return nil
	}
	s, e := store.Open(boot)
	if e != nil {
		return e
	}
	defer s.Close()
	switch command {
	case "check":
		if e = s.Check(context.Background()); e != nil {
			return e
		}
		rev, e := s.Active()
		if e != nil {
			return e
		}
		engine := proxy.New(boot, s.Key(), s, nil)
		compiled, e := engine.Compile(rev.Bundle)
		if e != nil {
			return e
		}
		compiled.Release()
		certs := tlsmgr.New(boot, s)
		defer certs.Close()
		if e = certs.Validate(rev.Bundle); e != nil {
			return e
		}
		fmt.Printf("Configuration valid; revision %d, CRS %s\n", rev.ID, policy.CRSVersion)
	case "backup":
		if *out == "" {
			return errors.New("--out is required")
		}
		password, e := readSecret(*passwordFile, "Backup password: ")
		if e != nil {
			return e
		}
		f, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		e = backup.Create(boot, s, password, f)
		closeErr := f.Close()
		if e = errors.Join(e, closeErr); e != nil {
			os.Remove(*out)
			return e
		}
		fmt.Println("Encrypted backup created. Keep the original master key separately.")
	case "reset-admin":
		password, e := readSecret(*passwordFile, "New password: ")
		if e != nil {
			return e
		}
		secret, codes, e := s.ResetUser(*username, password)
		if e != nil {
			return e
		}
		printEnrollment(*username, secret, codes)
	}
	return nil
}
func initialize(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	cfgPath := flags.String("config", "/etc/waf/waf.json", "new bootstrap configuration file")
	dir := flags.String("data-dir", "/var/lib/waf", "data directory")
	keyPath := flags.String("key-file", "", "master key file (default: beside configuration)")
	domain := flags.String("domain", "", "administration DNS name")
	email := flags.String("email", "", "ACME account email")
	passwordFile := flags.String("password-file", "", "protected initial password file")
	tokenFile := flags.String("cloudflare-token-file", "", "protected Cloudflare DNS API token file")
	zoneFile := flags.String("cloudflare-zone-token-file", "", "optional protected Cloudflare Zone:Read token file")
	username := flags.String("username", "admin", "initial administrator username")
	development := flags.Bool("development", false, "loopback HTTP only, for local development")
	staging := flags.Bool("staging", false, "use the Let's Encrypt staging CA")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if _, e := os.Stat(*cfgPath); !os.IsNotExist(e) {
		return errors.New("configuration already exists or is inaccessible")
	}
	b := config.DefaultBootstrap()
	var e error
	b.DataDir, e = filepath.Abs(*dir)
	if e != nil {
		return e
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(filepath.Dir(*cfgPath), "master.key")
	}
	b.MasterKeyFile, e = filepath.Abs(*keyPath)
	if e != nil {
		return e
	}
	b.AdminDomain = strings.ToLower(*domain)
	b.ACMEEmail = *email
	b.Development = *development
	if *staging {
		b.ACMECA = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	if b.Development {
		b.HTTPListen = "127.0.0.1:8080"
		b.HTTPSListen = ""
		if b.AdminDomain == "" {
			b.AdminDomain = "admin.localhost"
		}
	}
	if e = b.Validate(); e != nil {
		return e
	}
	password, e := readSecret(*passwordFile, "Initial administrator password (at least 12 characters): ")
	if e != nil {
		return e
	}
	if _, e = secure.Password(password); e != nil {
		return e
	}
	var credential tlsmgr.Credential
	if !b.Development {
		credential.APIToken, e = readSecret(*tokenFile, "Cloudflare DNS API token: ")
		if e != nil {
			return e
		}
		if *zoneFile != "" {
			credential.ZoneToken, e = readSecret(*zoneFile, "")
			if e != nil {
				return e
			}
		}
	}
	if e = os.MkdirAll(filepath.Dir(*cfgPath), 0750); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(b.MasterKeyFile), 0750); e != nil {
		return e
	}
	unlock, e := app.Lock(b.DataDir)
	if e != nil {
		return e
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(b.DataDir, "config.db")); !os.IsNotExist(err) {
		return errors.New("data directory is already initialized or inaccessible")
	}
	if e = secure.CreateKey(b.MasterKeyFile); e != nil {
		return e
	}
	s, e := store.Open(b)
	if e != nil {
		return e
	}
	defer s.Close()
	users, e := s.Users()
	if e != nil {
		return e
	}
	if len(users) != 0 {
		return errors.New("data directory is already initialized")
	}
	user, secret, codes, e := s.CreateUser(*username, password, "admin", "local-cli")
	if e != nil {
		return e
	}
	if !b.Development {
		raw, _ := json.Marshal(credential)
		if e = s.PutSecret("cloudflare", raw, "local-cli"); e != nil {
			return e
		}
	}
	raw, e := json.MarshalIndent(b, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(*cfgPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if e != nil {
		return e
	}
	_, e = f.Write(append(raw, '\n'))
	closeErr := f.Close()
	if e = errors.Join(e, closeErr); e != nil {
		return e
	}
	fmt.Println("Initialized:", *cfgPath)
	printEnrollment(user.Username, secret, codes)
	if b.Development {
		fmt.Printf("Local console: http://%s:8080 (development mode)\n", b.AdminDomain)
	} else {
		fmt.Printf("Console: https://%s after certificate issuance\n", b.AdminDomain)
	}
	return nil
}
func readSecret(path, prompt string) (string, error) {
	if path != "" {
		info, e := os.Stat(path)
		if e != nil {
			return "", e
		}
		if info.Mode().Perm()&0077 != 0 {
			return "", errors.New("secret input files must be 0600 or stricter")
		}
		if info.Size() > 8192 {
			return "", errors.New("secret file is too large")
		}
		b, e := os.ReadFile(path)
		return strings.TrimSpace(string(b)), e
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("use a protected --password-file or token file when stdin is not a terminal")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return strings.TrimSpace(string(b)), e
}
func printEnrollment(user, secret string, codes []string) {
	fmt.Println("Save these enrollment details privately; they are only shown now.")
	fmt.Println("TOTP secret:", secret)
	fmt.Println("TOTP URI:", "otpauth://totp/"+url.PathEscape("WAF:"+user)+"?secret="+secret+"&issuer=WAF&algorithm=SHA1&digits=6&period=30")
	fmt.Println("Recovery codes:")
	for _, code := range codes {
		fmt.Println(code)
	}
}
func doctor(b config.Bootstrap) error {
	fmt.Printf("Admin: %s\nData: %s\nCRS: %s\n", b.AdminDomain, b.DataDir, policy.CRSVersion)
	if _, e := secure.LoadKey(b.MasterKeyFile); e != nil {
		return e
	}
	if b.OpsListen == "" {
		return errors.New("ops listener is disabled")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, p := range []string{"/livez", "/readyz"} {
		resp, e := client.Get("http://" + b.OpsListen + p)
		if e != nil {
			return e
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		fmt.Printf("%s: %d %s", p, resp.StatusCode, body)
		if resp.StatusCode != 200 {
			return errors.New("service is not ready")
		}
	}
	return nil
}
func usage() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintln(w, "Usage: waf <init|serve|check|doctor|backup|restore|reset-admin|version> [options]")
	fmt.Fprintln(w, "Run waf <command> -h for options. Production requires Cloudflare DNS API tokens, an admin domain and TOTP.")
}
