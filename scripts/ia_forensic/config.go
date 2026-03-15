package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	VeloRaptorBin string `json:"velociraptor_bin"`
	OutputDir     string `json:"output_dir"`
	ReportsDir    string `json:"reports_dir"`
	UIPort        string `json:"ui_port"`
	ProxyURL      string `json:"proxy_url"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	ProxyAuthType string `json:"proxy_auth_type"`
	ProxyUser     string `json:"proxy_user"`
	ProxyPass     string `json:"proxy_pass"`
	MoteurDir     string `json:"moteur_dir"`
}

const defaultConfigPath = "../config/config.json"

func loadConfig() *Config {
	cfg := &Config{
		OutputDir:  "../collections",
		ReportsDir: "../reports",
		UIPort:     "8767",
		MoteurDir:  "",
	}
	// Chercher config.json dans plusieurs emplacements
	for _, p := range []string{defaultConfigPath, "config/config.json", "config.json"} {
		data, err := os.ReadFile(p)
		if err == nil {
			_ = json.Unmarshal(data, cfg)
			break
		}
	}
	if cfg.UIPort == "" {
		cfg.UIPort = "8767"
	}
	return cfg
}

func saveConfigToDisk(cfg *Config) error {
	paths := []string{defaultConfigPath, "config/config.json"}
	for _, p := range paths {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0600); err == nil {
			return nil
		}
	}
	return fmt.Errorf("impossible d'écrire config.json")
}

// ─── Log broadcaster ──────────────────────────────────────────────────────────

type logBroadcaster struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	history []string
}

var logHub = &logBroadcaster{clients: make(map[chan string]struct{})}

type logWriter struct{}

func (lw logWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	logHub.broadcast(line)
	fmt.Fprintln(os.Stderr, line)
	return len(p), nil
}

func (lb *logBroadcaster) broadcast(line string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.history = append(lb.history, line)
	if len(lb.history) > 400 {
		lb.history = lb.history[len(lb.history)-400:]
	}
	for ch := range lb.clients {
		select {
		case ch <- line:
		default:
		}
	}
}

func (lb *logBroadcaster) subscribe() chan string {
	ch := make(chan string, 128)
	lb.mu.Lock()
	lb.clients[ch] = struct{}{}
	lb.mu.Unlock()
	return ch
}

func (lb *logBroadcaster) unsubscribe(ch chan string) {
	lb.mu.Lock()
	delete(lb.clients, ch)
	lb.mu.Unlock()
	close(ch)
}

func (lb *logBroadcaster) getHistory() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	cp := make([]string, len(lb.history))
	copy(cp, lb.history)
	return cp
}

// ─── Base de données ──────────────────────────────────────────────────────────

var db *sql.DB
var dbMu sync.Mutex

func initDB(dir string) error {
	_ = os.MkdirAll(dir, 0755)
	dbMu.Lock()
	defer dbMu.Unlock()
	var err error
	dbPath := filepath.Join(dir, "velociraptor-ia.db")
	db, err = sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS collections (
			id          TEXT PRIMARY KEY,
			filename    TEXT NOT NULL,
			imported_at TEXT NOT NULL,
			hostname    TEXT,
			os_name     TEXT,
			artifacts   TEXT,
			status      TEXT DEFAULT 'imported',
			report_path TEXT
		);
		CREATE TABLE IF NOT EXISTS analyses (
			collection_id TEXT PRIMARY KEY,
			engine        TEXT,
			threat_level  TEXT,
			summary       TEXT,
			findings      TEXT,
			iocs          TEXT,
			mitre         TEXT,
			timeline      TEXT,
			recommendations TEXT,
			report_path   TEXT,
			created_at    TEXT
		);
	`)
	if err != nil {
		return err
	}
	log.Printf("[DB] Initialisée : %s", dbPath)
	return nil
}
