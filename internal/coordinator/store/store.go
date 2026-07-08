// Package store persists coordinator state in SQLite (modernc.org/sqlite,
// CGo-free). Single write connection to avoid SQLITE_BUSY; reads share it —
// at homelab scale contention is irrelevant.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/text"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("store: not found")

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS nodes (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    os               TEXT NOT NULL DEFAULT '',
    arch             TEXT NOT NULL DEFAULT '',
    role             TEXT NOT NULL DEFAULT 'node',
    wg_pubkey        TEXT NOT NULL UNIQUE,
    wg_listen_port   INTEGER NOT NULL DEFAULT 0,
    overlay_ip       TEXT NOT NULL UNIQUE,
    dns_name         TEXT NOT NULL DEFAULT '',
    auth_secret_hash TEXT NOT NULL,
    created_at       TIMESTAMP NOT NULL,
    last_seen        TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    name_hint  TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL,
    used_at    TIMESTAMP
);
CREATE TABLE IF NOT EXISTS static_peers (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    wg_pubkey  TEXT NOT NULL UNIQUE,
    wg_privkey TEXT NOT NULL,
    overlay_ip TEXT NOT NULL UNIQUE,
    dns_name   TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
    node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('local','observed')),
    addr       TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (node_id, kind, addr)
);
CREATE TABLE IF NOT EXISTS publishes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    listen_port INTEGER NOT NULL UNIQUE,
    target      TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    src_tags   TEXT NOT NULL DEFAULT '',
    dst_tags   TEXT NOT NULL DEFAULT '',
    protocol   TEXT NOT NULL DEFAULT 'any',
    ports      TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TIMESTAMP NOT NULL,
    kind       TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    message    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_id_desc ON events(id DESC);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO meta (key, value) VALUES ('netmap_version', '1');
`)
	if err != nil {
		return err
	}
	// Columns added after the first release (SQLite has no ADD COLUMN IF NOT
	// EXISTS — probe the schema instead).
	for _, ddl := range []string{
		`ALTER TABLE nodes ADD COLUMN routes_advertised TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN routes_enabled TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN lock_sig TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE static_peers ADD COLUMN lock_sig TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN approved INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE nodes ADD COLUMN tags TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE static_peers ADD COLUMN tags TEXT NOT NULL DEFAULT ''`,
	} {
		if err := s.addColumnIfMissing(ddl); err != nil {
			return err
		}
	}
	return nil
}

// addColumnIfMissing runs an ALTER TABLE ... ADD COLUMN, treating "duplicate
// column name" as success.
func (s *Store) addColumnIfMissing(ddl string) error {
	_, err := s.db.Exec(ddl)
	if err != nil && strings.Contains(err.Error(), "duplicate column name") {
		return nil
	}
	return err
}

type Node struct {
	ID             string
	Name           string
	OS             string
	Arch           string
	Role           string
	WGPubKey       string
	WGListenPort   int
	OverlayIP      string
	DNSName        string
	AuthSecretHash string
	CreatedAt      time.Time
	LastSeen       time.Time
	// Subnet router: RoutesAdvertised is what the agent reports, RoutesEnabled
	// is the admin-approved subset that actually enters netmaps.
	RoutesAdvertised []string
	RoutesEnabled    []string
	// LockSig: admin signature over (wg_pubkey, overlay_ip); cleared on rekey.
	LockSig string
	// Approved gates the node into the network (peer approval). Tags group
	// nodes for ACL policies.
	Approved bool
	Tags     []string
}

type StaticPeer struct {
	ID        string
	Name      string
	WGPubKey  string
	WGPrivKey string
	OverlayIP string
	DNSName   string
	CreatedAt time.Time
	LockSig   string
	Tags      []string
}

type Endpoint struct {
	NodeID    string
	Kind      string // "local" | "observed"
	Addr      string
	UpdatedAt time.Time
}

// --- netmap version ---

func (s *Store) NetmapVersion() (int64, error) {
	var v int64
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'netmap_version'`).Scan(&v)
	return v, err
}

func (s *Store) BumpNetmapVersion() (int64, error) {
	_, err := s.db.Exec(`UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'netmap_version'`)
	if err != nil {
		return 0, err
	}
	return s.NetmapVersion()
}

// --- enroll tokens (only the hash is stored) ---

func (s *Store) CreateEnrollToken(tokenHash, nameHint string, expiresAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO enroll_tokens (token_hash, name_hint, expires_at) VALUES (?, ?, ?)`,
		tokenHash, nameHint, expiresAt.UTC())
	return err
}

// ConsumeEnrollToken atomically marks a valid unused token as used and
// returns its name hint. ErrNotFound covers unknown, expired and reused.
func (s *Store) ConsumeEnrollToken(tokenHash string, now time.Time) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var hint string
	err = tx.QueryRow(`SELECT name_hint FROM enroll_tokens
		WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, tokenHash, now.UTC()).Scan(&hint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE enroll_tokens SET used_at = ? WHERE token_hash = ?`, now.UTC(), tokenHash); err != nil {
		return "", err
	}
	return hint, tx.Commit()
}

// --- nodes ---

func (s *Store) CreateNode(n Node) error {
	_, err := s.db.Exec(`INSERT INTO nodes
		(id, name, os, arch, role, wg_pubkey, wg_listen_port, overlay_ip, dns_name, auth_secret_hash, created_at, last_seen, approved, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.Name, n.OS, n.Arch, n.Role, n.WGPubKey, n.WGListenPort, n.OverlayIP, n.DNSName,
		n.AuthSecretHash, n.CreatedAt.UTC(), n.LastSeen.UTC(), n.Approved, text.JoinCSV(n.Tags))
	return err
}

const nodeCols = `id, name, os, arch, role, wg_pubkey, wg_listen_port, overlay_ip, dns_name, auth_secret_hash, created_at, last_seen, routes_advertised, routes_enabled, lock_sig, approved, tags`

func scanNode(row interface{ Scan(...any) error }) (Node, error) {
	var n Node
	var adv, en, tags string
	err := row.Scan(&n.ID, &n.Name, &n.OS, &n.Arch, &n.Role, &n.WGPubKey, &n.WGListenPort,
		&n.OverlayIP, &n.DNSName, &n.AuthSecretHash, &n.CreatedAt, &n.LastSeen, &adv, &en, &n.LockSig, &n.Approved, &tags)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	n.RoutesAdvertised, n.RoutesEnabled, n.Tags = text.SplitCSV(adv), text.SplitCSV(en), text.SplitCSV(tags)
	return n, err
}

// SetNodeApproved gates a node into the network.
func (s *Store) SetNodeApproved(id string, approved bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET approved = ? WHERE id = ?`, approved, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetNodeTags(id string, tags []string) error {
	res, err := s.db.Exec(`UPDATE nodes SET tags = ? WHERE id = ?`, text.JoinCSV(tags), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetStaticPeerTags(id string, tags []string) error {
	res, err := s.db.Exec(`UPDATE static_peers SET tags = ? WHERE id = ?`, text.JoinCSV(tags), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAdvertisedRoutes stores what the agent reports; enabled routes that are
// no longer advertised are dropped. Reports whether anything changed.
func (s *Store) SetAdvertisedRoutes(id string, routes []string) (bool, error) {
	n, err := s.NodeByID(id)
	if err != nil {
		return false, err
	}
	adv := text.JoinCSV(routes)
	stillAdvertised := map[string]bool{}
	for _, r := range routes {
		stillAdvertised[r] = true
	}
	var enabled []string
	for _, r := range n.RoutesEnabled {
		if stillAdvertised[r] {
			enabled = append(enabled, r)
		}
	}
	en := text.JoinCSV(enabled)
	if adv == text.JoinCSV(n.RoutesAdvertised) && en == text.JoinCSV(n.RoutesEnabled) {
		return false, nil
	}
	_, err = s.db.Exec(`UPDATE nodes SET routes_advertised = ?, routes_enabled = ? WHERE id = ?`, adv, en, id)
	return err == nil, err
}

// SetEnabledRoutes stores the admin-approved subset (caller validates it).
func (s *Store) SetEnabledRoutes(id string, routes []string) error {
	res, err := s.db.Exec(`UPDATE nodes SET routes_enabled = ? WHERE id = ?`, text.JoinCSV(routes), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) NodeByID(id string) (Node, error) {
	return scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
}

func (s *Store) NodeByAuthHash(hash string) (Node, error) {
	return scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE auth_secret_hash = ?`, hash))
}

func (s *Store) Nodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT ` + nodeCols + ` FROM nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) DeleteNode(id string) error {
	res, err := s.db.Exec(`DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TouchNode(id string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE nodes SET last_seen = ? WHERE id = ?`, now.UTC(), id)
	return err
}

// SetNodeKey stores a rotated WireGuard public key. The lock signature
// covers the old key, so it is cleared — the binding must be re-signed.
func (s *Store) SetNodeKey(id, pubkey string) error {
	res, err := s.db.Exec(`UPDATE nodes SET wg_pubkey = ?, lock_sig = '' WHERE id = ?`, pubkey, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetNodeLockSig(id, sig string) error {
	res, err := s.db.Exec(`UPDATE nodes SET lock_sig = ? WHERE id = ?`, sig, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetStaticPeerLockSig(id, sig string) error {
	res, err := s.db.Exec(`UPDATE static_peers SET lock_sig = ? WHERE id = ?`, sig, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ClearLockSigs() error {
	if _, err := s.db.Exec(`UPDATE nodes SET lock_sig = ''`); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE static_peers SET lock_sig = ''`)
	return err
}

// --- meta key/value (netmap version, lock settings) ---

// MetaGet returns "" for missing keys.
func (s *Store) MetaGet(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) MetaSet(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) MetaDelete(key string) error {
	_, err := s.db.Exec(`DELETE FROM meta WHERE key = ?`, key)
	return err
}

// --- static peers ---

func (s *Store) CreateStaticPeer(p StaticPeer) error {
	_, err := s.db.Exec(`INSERT INTO static_peers (id, name, wg_pubkey, wg_privkey, overlay_ip, dns_name, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.WGPubKey, p.WGPrivKey, p.OverlayIP, p.DNSName, p.CreatedAt.UTC())
	return err
}

func (s *Store) StaticPeerByID(id string) (StaticPeer, error) {
	var p StaticPeer
	var tags string
	err := s.db.QueryRow(`SELECT id, name, wg_pubkey, wg_privkey, overlay_ip, dns_name, created_at, lock_sig, tags
		FROM static_peers WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.WGPubKey, &p.WGPrivKey, &p.OverlayIP, &p.DNSName, &p.CreatedAt, &p.LockSig, &tags)
	if errors.Is(err, sql.ErrNoRows) {
		return StaticPeer{}, ErrNotFound
	}
	p.Tags = text.SplitCSV(tags)
	return p, err
}

func (s *Store) DeleteStaticPeer(id string) error {
	res, err := s.db.Exec(`DELETE FROM static_peers WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) StaticPeers() ([]StaticPeer, error) {
	rows, err := s.db.Query(`SELECT id, name, wg_pubkey, wg_privkey, overlay_ip, dns_name, created_at, lock_sig, tags FROM static_peers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StaticPeer
	for rows.Next() {
		var p StaticPeer
		var tags string
		if err := rows.Scan(&p.ID, &p.Name, &p.WGPubKey, &p.WGPrivKey, &p.OverlayIP, &p.DNSName, &p.CreatedAt, &p.LockSig, &tags); err != nil {
			return nil, err
		}
		p.Tags = text.SplitCSV(tags)
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- ACL policies ---

type Policy struct {
	ID        string
	Name      string
	SrcTags   []string
	DstTags   []string
	Protocol  string // "any" | "tcp" | "udp" | "icmp"
	Ports     []string
	Enabled   bool
	CreatedAt time.Time
}

func (s *Store) CreatePolicy(p Policy) error {
	_, err := s.db.Exec(`INSERT INTO policies (id, name, src_tags, dst_tags, protocol, ports, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, text.JoinCSV(p.SrcTags), text.JoinCSV(p.DstTags), p.Protocol, text.JoinCSV(p.Ports), p.Enabled, p.CreatedAt.UTC())
	return err
}

func (s *Store) Policies() ([]Policy, error) {
	rows, err := s.db.Query(`SELECT id, name, src_tags, dst_tags, protocol, ports, enabled, created_at FROM policies ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		var src, dst, ports string
		if err := rows.Scan(&p.ID, &p.Name, &src, &dst, &p.Protocol, &ports, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.SrcTags, p.DstTags, p.Ports = text.SplitCSV(src), text.SplitCSV(dst), text.SplitCSV(ports)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeletePolicy(id string) error {
	res, err := s.db.Exec(`DELETE FROM policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- events (activity log) ---

type Event struct {
	ID      int64
	TS      time.Time
	Kind    string
	Actor   string
	Message string
}

// AddEvent appends one entry and trims the log to the most recent
// eventRetention rows.
const eventRetention = 5000

func (s *Store) AddEvent(kind, actor, message string, now time.Time) (Event, error) {
	res, err := s.db.Exec(`INSERT INTO events (ts, kind, actor, message) VALUES (?, ?, ?, ?)`,
		now.UTC(), kind, actor, message)
	if err != nil {
		return Event{}, err
	}
	id, _ := res.LastInsertId()
	_, _ = s.db.Exec(`DELETE FROM events WHERE id <= ?`, id-eventRetention)
	return Event{ID: id, TS: now.UTC(), Kind: kind, Actor: actor, Message: message}, nil
}

// Events returns the newest entries first; beforeID=0 means from the top.
func (s *Store) Events(beforeID int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, ts, kind, actor, message FROM events`
	args := []any{}
	if beforeID > 0 {
		q += ` WHERE id < ?`
		args = append(args, beforeID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.Actor, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- publishes (hub TCP forwarders exposing overlay services publicly) ---

type Publish struct {
	ID         string
	Name       string
	ListenPort int
	Target     string // "overlay-ip:port" or "name.kai:port"
	CreatedAt  time.Time
}

func (s *Store) CreatePublish(p Publish) error {
	_, err := s.db.Exec(`INSERT INTO publishes (id, name, listen_port, target, created_at) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.ListenPort, p.Target, p.CreatedAt.UTC())
	return err
}

func (s *Store) Publishes() ([]Publish, error) {
	rows, err := s.db.Query(`SELECT id, name, listen_port, target, created_at FROM publishes ORDER BY listen_port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Publish
	for rows.Next() {
		var p Publish
		if err := rows.Scan(&p.ID, &p.Name, &p.ListenPort, &p.Target, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeletePublish(id string) error {
	res, err := s.db.Exec(`DELETE FROM publishes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- endpoints (M3 discovery data) ---

// ReplaceEndpoints swaps all endpoints of the given kind for a node and
// reports whether the address set actually changed (the timestamps are
// refreshed either way — freshness feeds M3 candidate filtering).
func (s *Store) ReplaceEndpoints(nodeID, kind string, addrs []string, now time.Time) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT addr FROM endpoints WHERE node_id = ? AND kind = ?`, nodeID, kind)
	if err != nil {
		return false, err
	}
	old := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return false, err
		}
		old[a] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	changed := len(old) != len(addrs)
	for _, a := range addrs {
		if !old[a] {
			changed = true
		}
	}

	if _, err := tx.Exec(`DELETE FROM endpoints WHERE node_id = ? AND kind = ?`, nodeID, kind); err != nil {
		return false, err
	}
	for _, a := range addrs {
		if _, err := tx.Exec(`INSERT INTO endpoints (node_id, kind, addr, updated_at) VALUES (?, ?, ?, ?)`,
			nodeID, kind, a, now.UTC()); err != nil {
			return false, err
		}
	}
	return changed, tx.Commit()
}

func (s *Store) EndpointsByNode() (map[string][]Endpoint, error) {
	rows, err := s.db.Query(`SELECT node_id, kind, addr, updated_at FROM endpoints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.NodeID, &e.Kind, &e.Addr, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out[e.NodeID] = append(out[e.NodeID], e)
	}
	return out, rows.Err()
}

// AllocatedIPs returns every overlay IP currently in use (nodes + static peers).
func (s *Store) AllocatedIPs() (map[string]bool, error) {
	out := map[string]bool{}
	for _, q := range []string{`SELECT overlay_ip FROM nodes`, `SELECT overlay_ip FROM static_peers`} {
		rows, err := s.db.Query(q)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				rows.Close()
				return nil, err
			}
			out[ip] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}
