package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
	"waf/internal/config"
	"waf/internal/secure"
)

var ErrConflict = errors.New("configuration changed; reload before saving")
var ErrAuth = errors.New("invalid credentials")
var dummyOnce sync.Once
var dummyPassword string

type Store struct {
	DB          *sql.DB
	EventsDB    *sql.DB
	key         []byte
	dir         string
	queue       chan Event
	done        chan struct{}
	wg          sync.WaitGroup
	Dropped     atomic.Uint64
	WriteErrors atomic.Uint64
	closeOnce   sync.Once
	retention   int
	maxRows     int
}
type Revision struct {
	ID         int64         `json:"id"`
	Created    string        `json:"created"`
	Actor      string        `json:"actor"`
	CRSVersion string        `json:"crs_version"`
	Bundle     config.Bundle `json:"bundle"`
}
type Draft struct {
	BaseRevision int64         `json:"base_revision"`
	Version      int64         `json:"version"`
	Bundle       config.Bundle `json:"bundle"`
}
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
	Created  string `json:"created"`
}
type Session struct {
	User    User
	CSRF    string
	Expires time.Time
}
type Event struct {
	ID             int64  `json:"id"`
	Time           string `json:"time"`
	SiteID         string `json:"site_id"`
	RequestID      string `json:"request_id"`
	ClientIP       string `json:"client_ip"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	Action         string `json:"action"`
	ChallengeMode  string `json:"challenge_mode,omitempty"`
	RuleID         string `json:"rule_id,omitempty"`
	Message        string `json:"message,omitempty"`
	DurationMS     int64  `json:"duration_ms"`
	Bytes          int64  `json:"bytes"`
	Inspection     string `json:"inspection"`
	Revision       int64  `json:"revision"`
	MatchedRuleIDs []int  `json:"matched_rule_ids,omitempty"`
}
type Audit struct {
	ID     int64  `json:"id"`
	Time   string `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}
type EventFilter struct {
	SiteID string
	Action string
	Before int64
	Limit  int
}

func Open(boot config.Bootstrap) (*Store, error) {
	dummyOnce.Do(func() { dummyPassword, _ = secure.Password("not a real account password") })
	key, e := secure.LoadKey(boot.MasterKeyFile)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(boot.DataDir, 0700); e != nil {
		return nil, e
	}
	if e = os.Chmod(boot.DataDir, 0700); e != nil {
		return nil, e
	}
	s := &Store{key: key, dir: boot.DataDir, queue: make(chan Event, 4096), done: make(chan struct{}), retention: boot.EventRetentionDays, maxRows: boot.EventMaxRows}
	open := func(name string) (*sql.DB, error) {
		p := filepath.Join(boot.DataDir, name)
		f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return nil, e
		}
		f.Close()
		if e = os.Chmod(p, 0600); e != nil {
			return nil, e
		}
		db, e := sql.Open("sqlite", p)
		if e != nil {
			return nil, e
		}
		db.SetMaxOpenConns(1)
		for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=FULL", "PRAGMA journal_size_limit=8388608"} {
			if _, e = db.Exec(q); e != nil {
				db.Close()
				return nil, e
			}
		}
		return db, nil
	}
	if s.DB, e = open("config.db"); e != nil {
		return nil, e
	}
	if s.EventsDB, e = open("events.db"); e != nil {
		s.DB.Close()
		return nil, e
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)`,
		`INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version)`,
		`CREATE TABLE IF NOT EXISTS revisions(id INTEGER PRIMARY KEY AUTOINCREMENT,created TEXT NOT NULL,actor TEXT NOT NULL,crs_version TEXT NOT NULL,body TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS draft(id INTEGER PRIMARY KEY CHECK(id=1),base_revision INTEGER NOT NULL,version INTEGER NOT NULL,body TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS secrets(name TEXT PRIMARY KEY,value BLOB NOT NULL,updated TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,role TEXT NOT NULL,disabled INTEGER NOT NULL DEFAULT 0,password TEXT NOT NULL,totp BLOB NOT NULL,last_step INTEGER NOT NULL DEFAULT 0,recovery TEXT NOT NULL,created TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL)`,
	} {
		if _, e = s.DB.Exec(q); e != nil {
			s.Close()
			return nil, e
		}
	}
	var version int
	if e = s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&version); e != nil || version != 1 {
		s.Close()
		return nil, errors.New("unsupported database schema")
	}
	for _, q := range []string{`CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT NOT NULL,site_id TEXT NOT NULL,action TEXT NOT NULL,status INTEGER NOT NULL,body TEXT NOT NULL)`, `CREATE INDEX IF NOT EXISTS events_site_id ON events(site_id,id)`, `CREATE INDEX IF NOT EXISTS events_time ON events(time)`, `CREATE INDEX IF NOT EXISTS events_action_id ON events(action,id)`} {
		if _, e = s.EventsDB.Exec(q); e != nil {
			s.Close()
			return nil, e
		}
	}
	if _, e = s.DB.Exec(`INSERT OR IGNORE INTO settings(key,value) VALUES('active_revision','0')`); e != nil {
		s.Close()
		return nil, e
	}
	if _, e = s.DB.Exec(`INSERT OR IGNORE INTO draft VALUES(1,0,1,'{"sites":[]}')`); e != nil {
		s.Close()
		return nil, e
	}
	s.wg.Add(1)
	go s.eventWorker()
	return s, nil
}
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.wg.Wait()
		if s.DB != nil {
			s.DB.Close()
		}
		if s.EventsDB != nil {
			s.EventsDB.Close()
		}
	})
	return nil
}
func (s *Store) Key() []byte { return append([]byte{}, s.key...) }
func now() string            { return time.Now().UTC().Format(time.RFC3339Nano) }
func (s *Store) Active() (Revision, error) {
	var id int64
	if e := s.DB.QueryRow(`SELECT value FROM settings WHERE key='active_revision'`).Scan(&id); e != nil {
		return Revision{}, e
	}
	if id == 0 {
		return Revision{Bundle: config.Bundle{Sites: []config.Site{}}}, nil
	}
	return s.Revision(id)
}
func (s *Store) Revision(id int64) (Revision, error) {
	var r Revision
	var body string
	e := s.DB.QueryRow(`SELECT id,created,actor,crs_version,body FROM revisions WHERE id=?`, id).Scan(&r.ID, &r.Created, &r.Actor, &r.CRSVersion, &body)
	if e == nil {
		e = json.Unmarshal([]byte(body), &r.Bundle)
	}
	return r, e
}
func (s *Store) Revisions() ([]Revision, error) {
	rows, e := s.DB.Query(`SELECT id,created,actor,crs_version FROM revisions ORDER BY id DESC LIMIT 100`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Revision{}
	for rows.Next() {
		var r Revision
		if e = rows.Scan(&r.ID, &r.Created, &r.Actor, &r.CRSVersion); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Draft() (Draft, error) {
	var d Draft
	var body string
	e := s.DB.QueryRow(`SELECT base_revision,version,body FROM draft WHERE id=1`).Scan(&d.BaseRevision, &d.Version, &body)
	if e == nil {
		e = json.Unmarshal([]byte(body), &d.Bundle)
	}
	return d, e
}
func auditTx(tx *sql.Tx, actor, action, detail string) error {
	_, e := tx.Exec(`INSERT INTO audit(time,actor,action,detail) VALUES(?,?,?,?)`, now(), actor, action, detail)
	return e
}
func (s *Store) SaveDraft(d Draft, actor string) (Draft, error) {
	body, e := json.Marshal(d.Bundle)
	if e != nil {
		return d, e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return d, e
	}
	defer tx.Rollback()
	res, e := tx.Exec(`UPDATE draft SET body=?,version=version+1 WHERE id=1 AND version=? AND base_revision=?`, string(body), d.Version, d.BaseRevision)
	if e != nil {
		return d, e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return d, ErrConflict
	}
	if e = auditTx(tx, actor, "draft.save", fmt.Sprint(d.Version)); e != nil {
		return d, e
	}
	if e = tx.Commit(); e != nil {
		return d, e
	}
	d.Version++
	return d, nil
}
func (s *Store) Publish(d Draft, actor, crsVersion string) (Revision, error) {
	body, e := json.Marshal(d.Bundle)
	if e != nil {
		return Revision{}, e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return Revision{}, e
	}
	defer tx.Rollback()
	var version, base, active int64
	if e = tx.QueryRow(`SELECT version,base_revision FROM draft WHERE id=1`).Scan(&version, &base); e != nil {
		return Revision{}, e
	}
	if e = tx.QueryRow(`SELECT value FROM settings WHERE key='active_revision'`).Scan(&active); e != nil {
		return Revision{}, e
	}
	if version != d.Version || base != d.BaseRevision || base != active {
		return Revision{}, ErrConflict
	}
	r := Revision{Created: now(), Actor: actor, CRSVersion: crsVersion, Bundle: d.Bundle}
	res, e := tx.Exec(`INSERT INTO revisions(created,actor,crs_version,body) VALUES(?,?,?,?)`, r.Created, actor, crsVersion, string(body))
	if e != nil {
		return r, e
	}
	r.ID, e = res.LastInsertId()
	if e != nil {
		return r, e
	}
	if _, e = tx.Exec(`UPDATE settings SET value=? WHERE key='active_revision'`, r.ID); e != nil {
		return r, e
	}
	if _, e = tx.Exec(`UPDATE draft SET base_revision=?,version=version+1,body=? WHERE id=1`, r.ID, string(body)); e != nil {
		return r, e
	}
	if e = auditTx(tx, actor, "config.publish", fmt.Sprintf("revision=%d CRS=%s", r.ID, crsVersion)); e != nil {
		return r, e
	}
	_, e = tx.Exec(`DELETE FROM revisions WHERE id NOT IN(SELECT id FROM revisions ORDER BY id DESC LIMIT 100)`)
	if e != nil {
		return r, e
	}
	e = tx.Commit()
	return r, e
}
func (s *Store) PutSecret(name string, value []byte, actor string) error {
	if !config.ValidID(name) {
		return errors.New("invalid secret name")
	}
	enc, e := secure.Seal(s.key, "credential:"+name, value)
	if e != nil {
		return e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO secrets(name,value,updated) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated=excluded.updated`, name, enc, now()); e != nil {
		return e
	}
	if e = auditTx(tx, actor, "credential.update", name); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Secret(name string) ([]byte, error) {
	var b []byte
	if e := s.DB.QueryRow(`SELECT value FROM secrets WHERE name=?`, name).Scan(&b); e != nil {
		return nil, e
	}
	return secure.Open(s.key, "credential:"+name, b)
}
func (s *Store) Secrets() ([]map[string]string, error) {
	rows, e := s.DB.Query(`SELECT name,updated FROM secrets ORDER BY name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var n, t string
		if e = rows.Scan(&n, &t); e != nil {
			return nil, e
		}
		out = append(out, map[string]string{"name": n, "updated": t})
	}
	return out, rows.Err()
}
func (s *Store) CreateUser(username, password, role, actor string) (User, string, []string, error) {
	u := User{ID: secure.Random(16), Username: username, Role: role, Created: now()}
	if !config.ValidID(username) || !validRole(role) {
		return u, "", nil, errors.New("invalid username or role")
	}
	hash, e := secure.Password(password)
	if e != nil {
		return u, "", nil, e
	}
	secret := secure.TOTPSecret()
	enc, e := secure.Seal(s.key, "totp:"+u.ID, []byte(secret))
	if e != nil {
		return u, "", nil, e
	}
	codes, hashed := recoveryCodes()
	raw, _ := json.Marshal(hashed)
	tx, e := s.DB.Begin()
	if e != nil {
		return u, "", nil, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO users(id,username,role,password,totp,recovery,created) VALUES(?,?,?,?,?,?,?)`, u.ID, username, role, hash, enc, string(raw), u.Created); e != nil {
		return u, "", nil, e
	}
	if e = auditTx(tx, actor, "user.create", username+" role="+role); e != nil {
		return u, "", nil, e
	}
	if e = tx.Commit(); e != nil {
		return u, "", nil, e
	}
	return u, secret, codes, nil
}
func recoveryCodes() ([]string, []string) {
	codes := []string{}
	hashes := []string{}
	for i := 0; i < 8; i++ {
		c := secure.Random(16)
		codes = append(codes, c)
		hashes = append(hashes, secure.Digest(c))
	}
	return codes, hashes
}
func validRole(r string) bool { return r == "admin" || r == "operator" || r == "viewer" }
func (s *Store) Users() ([]User, error) {
	rows, e := s.DB.Query(`SELECT id,username,role,disabled,created FROM users ORDER BY username`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if e = rows.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.Created); e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) UpdateUser(id, role string, disabled bool, actor string) error {
	if !validRole(role) {
		return errors.New("invalid role")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var currentRole string
	var oldDisabled bool
	if e = tx.QueryRow(`SELECT role,disabled FROM users WHERE id=?`, id).Scan(&currentRole, &oldDisabled); e != nil {
		return e
	}
	if currentRole == "admin" && !oldDisabled && (role != "admin" || disabled) {
		var n int
		if e = tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0`).Scan(&n); e != nil {
			return e
		}
		if n <= 1 {
			return errors.New("cannot disable the last administrator")
		}
	}
	if _, e = tx.Exec(`UPDATE users SET role=?,disabled=? WHERE id=?`, role, disabled, id); e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id); e != nil {
		return e
	}
	if e = auditTx(tx, actor, "user.update", id+" role="+role); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Authenticate(username, password, code string, development bool) (User, error) {
	var u User
	var hash string
	var enc []byte
	e := s.DB.QueryRow(`SELECT id,username,role,disabled,created,password,totp FROM users WHERE username=?`, username).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.Created, &hash, &enc)
	if e != nil {
		secure.VerifyPassword(dummyPassword, password)
		return u, ErrAuth
	}
	if !secure.VerifyPassword(hash, password) || u.Disabled {
		return u, ErrAuth
	}
	secret, e := secure.Open(s.key, "totp:"+u.ID, enc)
	if e != nil {
		return u, ErrAuth
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return u, e
	}
	defer tx.Rollback()
	var step int64
	var raw string
	var disabled bool
	if e = tx.QueryRow(`SELECT last_step,recovery,disabled FROM users WHERE id=?`, u.ID).Scan(&step, &raw, &disabled); e != nil || disabled {
		return u, ErrAuth
	}
	next, ok := secure.VerifyTOTP(string(secret), code, time.Now(), step)
	if development && code == "" {
		ok = true
		next = step
	}
	if !ok {
		var codes []string
		if e = json.Unmarshal([]byte(raw), &codes); e != nil {
			return u, ErrAuth
		}
		for i, c := range codes {
			if secure.Equal(c, secure.Digest(code)) {
				codes = append(codes[:i], codes[i+1:]...)
				ok = true
				break
			}
		}
		if !ok {
			return u, ErrAuth
		}
		b, _ := json.Marshal(codes)
		raw = string(b)
		next = step
	}
	if _, e = tx.Exec(`UPDATE users SET last_step=?,recovery=? WHERE id=?`, next, raw, u.ID); e != nil {
		return u, e
	}
	if e = auditTx(tx, username, "auth.login", ""); e != nil {
		return u, e
	}
	return u, tx.Commit()
}
func (s *Store) NewSession(u User) (token, csrf string, err error) {
	token = secure.Random(32)
	csrf = secure.Random(32)
	_, err = s.DB.Exec(`INSERT INTO sessions(token,user_id,csrf,expires) VALUES(?,?,?,?)`, secure.Digest(token), u.ID, csrf, time.Now().Add(8*time.Hour).Unix())
	return
}
func (s *Store) Session(token string) (Session, error) {
	var out Session
	var exp int64
	if len(token) != 43 {
		return out, ErrAuth
	}
	e := s.DB.QueryRow(`SELECT u.id,u.username,u.role,u.disabled,u.created,s.csrf,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?`, secure.Digest(token)).Scan(&out.User.ID, &out.User.Username, &out.User.Role, &out.User.Disabled, &out.User.Created, &out.CSRF, &exp)
	if e != nil || out.User.Disabled || time.Now().Unix() >= exp {
		return out, ErrAuth
	}
	out.Expires = time.Unix(exp, 0)
	return out, nil
}
func (s *Store) DeleteSession(token string) error {
	_, e := s.DB.Exec(`DELETE FROM sessions WHERE token=?`, secure.Digest(token))
	return e
}
func (s *Store) ResetUser(username, password string) (string, []string, error) {
	hash, e := secure.Password(password)
	if e != nil {
		return "", nil, e
	}
	var id string
	if e = s.DB.QueryRow(`SELECT id FROM users WHERE username=?`, username).Scan(&id); e != nil {
		return "", nil, e
	}
	secret := secure.TOTPSecret()
	enc, e := secure.Seal(s.key, "totp:"+id, []byte(secret))
	if e != nil {
		return "", nil, e
	}
	codes, hashes := recoveryCodes()
	raw, _ := json.Marshal(hashes)
	tx, e := s.DB.Begin()
	if e != nil {
		return "", nil, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE users SET password=?,totp=?,recovery=?,last_step=0,disabled=0 WHERE id=?`, hash, enc, string(raw), id); e != nil {
		return "", nil, e
	}
	if _, e = tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id); e != nil {
		return "", nil, e
	}
	if e = auditTx(tx, "local-cli", "user.reset", username); e != nil {
		return "", nil, e
	}
	return secret, codes, tx.Commit()
}
func (s *Store) Audit(actor, action, detail string) error {
	_, e := s.DB.Exec(`INSERT INTO audit(time,actor,action,detail) VALUES(?,?,?,?)`, now(), actor, action, detail)
	return e
}
func (s *Store) Audits(before int64) ([]Audit, error) {
	if before <= 0 {
		before = 1 << 62
	}
	rows, e := s.DB.Query(`SELECT id,time,actor,action,detail FROM audit WHERE id<? ORDER BY id DESC LIMIT 100`, before)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		if e = rows.Scan(&a.ID, &a.Time, &a.Actor, &a.Action, &a.Detail); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) Record(e Event) {
	if e.Time == "" {
		e.Time = now()
	}
	e.Path = truncate(e.Path, 512)
	e.Message = truncate(e.Message, 256)
	select {
	case s.queue <- e:
	default:
		s.Dropped.Add(1)
	}
}
func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
func (s *Store) eventWorker() {
	defer s.wg.Done()
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	prune := time.NewTicker(time.Minute)
	defer prune.Stop()
	batch := make([]Event, 0, 128)
	write := func() {
		if len(batch) == 0 {
			return
		}
		tx, e := s.EventsDB.Begin()
		if e == nil {
			for _, v := range batch {
				b, _ := json.Marshal(v)
				_, e = tx.Exec(`INSERT INTO events(time,site_id,action,status,body) VALUES(?,?,?,?,?)`, v.Time, v.SiteID, v.Action, v.Status, string(b))
				if e != nil {
					break
				}
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		if e != nil {
			s.WriteErrors.Add(1)
			s.Dropped.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
			if len(batch) >= 128 {
				write()
			}
		case <-flush.C:
			write()
		case <-prune.C:
			write()
			s.prune()
		case <-s.done:
			for {
				select {
				case e := <-s.queue:
					batch = append(batch, e)
					if len(batch) >= 128 {
						write()
					}
				default:
					write()
					return
				}
			}
		}
	}
}
func (s *Store) prune() {
	cut := time.Now().UTC().AddDate(0, 0, -s.retention).Format(time.RFC3339Nano)
	if _, e := s.EventsDB.Exec(`DELETE FROM events WHERE time<? OR id <= COALESCE((SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?),0)`, cut, s.maxRows); e != nil {
		s.WriteErrors.Add(1)
	}
	s.EventsDB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	s.DB.Exec(`DELETE FROM sessions WHERE expires<?`, time.Now().Unix())
	s.DB.Exec(`DELETE FROM audit WHERE time<? OR id<=COALESCE((SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 200000),0)`, time.Now().UTC().AddDate(0, 0, -90).Format(time.RFC3339Nano))
}
func (s *Store) Events(f EventFilter) ([]Event, error) {
	if f.Limit < 1 || f.Limit > 200 {
		f.Limit = 100
	}
	if f.Before <= 0 {
		f.Before = 1 << 62
	}
	query := `SELECT id,body FROM events WHERE id<?`
	args := []any{f.Before}
	if f.SiteID != "" {
		query += ` AND site_id=?`
		args = append(args, f.SiteID)
	}
	if f.Action != "" {
		query += ` AND action=?`
		args = append(args, f.Action)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, e := s.EventsDB.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var id int64
		var body string
		var event Event
		if e = rows.Scan(&id, &body); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(body), &event); e != nil {
			return nil, e
		}
		event.ID = id
		out = append(out, event)
	}
	return out, rows.Err()
}
func (s *Store) Stats() (map[string]int64, error) {
	out := map[string]int64{}
	rows, e := s.EventsDB.Query(`SELECT action,COUNT(*) FROM events WHERE time>=? GROUP BY action`, time.Now().UTC().Add(-24*time.Hour).Format(time.RFC3339Nano))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if e = rows.Scan(&k, &n); e != nil {
			return nil, e
		}
		out[k] = n
	}
	out["log_dropped"] = int64(s.Dropped.Load())
	out["log_write_errors"] = int64(s.WriteErrors.Load())
	return out, rows.Err()
}
func (s *Store) Check(ctx context.Context) error {
	for _, db := range []*sql.DB{s.DB, s.EventsDB} {
		var result string
		if e := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); e != nil {
			return e
		}
		if result != "ok" {
			return errors.New(result)
		}
	}
	return nil
}
func (s *Store) Snapshot(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for name, db := range map[string]*sql.DB{"config.db": s.DB, "events.db": s.EventsDB} {
		p := filepath.Join(dir, name)
		if _, e := db.Exec(`VACUUM INTO ?`, p); e != nil {
			return e
		}
		if e := os.Chmod(p, 0600); e != nil {
			return e
		}
	}
	return nil
}
