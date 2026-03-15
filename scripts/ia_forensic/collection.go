package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CollectionInfo est une collection importée en DB.
type CollectionInfo struct {
	ID         string `json:"id"`
	Filename   string `json:"filename"`
	ImportedAt string `json:"imported_at"`
	Hostname   string `json:"hostname"`
	OSName     string `json:"os_name"`
	Artifacts  string `json:"artifacts"`
	Status     string `json:"status"`
	ReportPath string `json:"report_path"`
}

// ArtifactData est un ensemble de lignes d'un artefact.
type ArtifactData struct {
	Name string                   `json:"name"`
	Rows []map[string]interface{} `json:"rows"`
}

// ParsedCollection contient toutes les données extraites d'un ZIP Velociraptor.
type ParsedCollection struct {
	Hostname  string
	OSName    string
	Artifacts []ArtifactData
}

// parseVelociraptorZIP extrait les données d'un ZIP de collecte Velociraptor.
// Structure attendue du ZIP (offline collector) :
//
//	results/<ArtifactName>/upload.json  → métadonnées
//	results/<ArtifactName>/<file>.json  → résultats JSONL (une ligne = un objet JSON)
//	collection_context.json             → infos hôte (hostname, OS, etc.)
func parseVelociraptorZIP(zipPath string) (*ParsedCollection, error) {
	rc, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("ouverture ZIP : %w", err)
	}
	defer rc.Close()

	result := &ParsedCollection{
		Hostname: filepath.Base(strings.TrimSuffix(zipPath, filepath.Ext(zipPath))),
		OSName:   "Windows",
	}
	artMap := make(map[string]*ArtifactData)

	for _, f := range rc.File {
		name := filepath.ToSlash(f.Name)

		// ── Métadonnées hôte ─────────────────────────────────────────────────
		if strings.HasSuffix(name, "collection_context.json") ||
			strings.HasSuffix(name, "client_info.json") {
			fr, e := f.Open()
			if e == nil {
				var info map[string]interface{}
				if json.NewDecoder(fr).Decode(&info) == nil {
					if h, ok := getString(info, "Hostname", "hostname"); ok {
						result.Hostname = h
					}
					if o, ok := getString(info, "OS", "os", "Platform"); ok {
						result.OSName = o
					}
				}
				fr.Close()
			}
			continue
		}

		// ── Résultats d'artefacts (JSON/JSONL) ───────────────────────────────
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		// Ignorer les fichiers de contrôle
		if strings.Contains(name, "upload.json") || strings.Contains(name, "context.json") {
			continue
		}

		// Extraire le nom de l'artefact depuis le chemin
		artName := extractArtifactName(name)
		if artName == "" {
			continue
		}

		fr, e := f.Open()
		if e != nil {
			continue
		}
		scanner := bufio.NewScanner(fr)
		scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024) // 4 Mo buffer

		if _, exists := artMap[artName]; !exists {
			artMap[artName] = &ArtifactData{Name: artName}
		}

		count := 0
		for scanner.Scan() && count < 100 { // max 100 lignes par artefact
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var row map[string]interface{}
			if json.Unmarshal(line, &row) == nil {
				artMap[artName].Rows = append(artMap[artName].Rows, row)
				count++
			}
		}
		fr.Close()
	}

	// Trier les artefacts par nom
	var artNames []string
	for k := range artMap {
		artNames = append(artNames, k)
	}
	sort.Strings(artNames)
	for _, n := range artNames {
		result.Artifacts = append(result.Artifacts, *artMap[n])
	}

	return result, nil
}

// extractArtifactName extrait le nom d'un artefact depuis un chemin de fichier ZIP.
func extractArtifactName(path string) string {
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if strings.HasPrefix(p, "Windows.") ||
			strings.HasPrefix(p, "Linux.") ||
			strings.HasPrefix(p, "Generic.") ||
			strings.HasPrefix(p, "MacOS.") {
			return strings.TrimSuffix(p, ".json")
		}
	}
	// Fallback : prendre le répertoire parent du fichier JSON
	if len(parts) >= 2 {
		parent := parts[len(parts)-2]
		if parent != "results" && parent != "" && !strings.HasSuffix(parent, ".json") {
			return parent
		}
	}
	return ""
}

func getString(m map[string]interface{}, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// ─── Handlers HTTP ────────────────────────────────────────────────────────────

func handleUploadCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST requis"}`, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<30) // 4 Go max
	if err := r.ParseMultipartForm(1 << 30); err != nil {
		http.Error(w, `{"error":"fichier trop volumineux (max 4 Go)"}`, http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("collection")
	if err != nil {
		http.Error(w, `{"error":"champ 'collection' manquant"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	cfgMu.RLock()
	outDir := currentCfg.OutputDir
	cfgMu.RUnlock()
	_ = os.MkdirAll(outDir, 0755)

	id := fmt.Sprintf("col_%s", time.Now().Format("20060102_150405"))
	destPath := filepath.Join(outDir, id+"_"+header.Filename)

	// Lire et écrire
	buf := make([]byte, 32*1024)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, `{"error":"création fichier"}`, http.StatusInternalServerError)
		return
	}
	totalBytes := 0
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			dest.Write(buf[:n])
			totalBytes += n
		}
		if readErr != nil {
			break
		}
	}
	dest.Close()

	log.Printf("[COLLECTION] Import : %s (%d octets)", header.Filename, totalBytes)

	// Parser le ZIP
	parsed, parseErr := parseVelociraptorZIP(destPath)
	hostname := "inconnu"
	osName := "Windows"
	var artNames []string
	if parseErr == nil && parsed != nil {
		hostname = parsed.Hostname
		osName = parsed.OSName
		for _, a := range parsed.Artifacts {
			artNames = append(artNames, a.Name)
		}
	} else {
		log.Printf("[COLLECTION] Avertissement parsing : %v", parseErr)
	}
	artStr := strings.Join(artNames, ",")
	status := "imported"
	if parseErr != nil {
		status = "imported_partial"
	}

	log.Printf("[COLLECTION] Hôte=%s OS=%s Artefacts=%d", hostname, osName, len(artNames))

	// DB
	dbMu.Lock()
	if db != nil {
		_, _ = db.Exec(`INSERT OR REPLACE INTO collections
			(id, filename, imported_at, hostname, os_name, artifacts, status, report_path)
			VALUES (?,?,?,?,?,?,?,?)`,
			id, destPath, time.Now().Format(time.RFC3339),
			hostname, osName, artStr, status, "")
	}
	dbMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]string{
		"id":        id,
		"hostname":  hostname,
		"os":        osName,
		"status":    status,
		"artifacts": fmt.Sprintf("%d", len(artNames)),
	})
	w.Write(resp)
}

func handleListCollections(w http.ResponseWriter, r *http.Request) {
	dbMu.Lock()
	defer dbMu.Unlock()
	if db == nil {
		w.Write([]byte("[]"))
		return
	}
	rows, err := db.Query(`
		SELECT id, filename, imported_at, hostname, os_name, artifacts, status, report_path
		FROM collections ORDER BY imported_at DESC`)
	if err != nil {
		http.Error(w, `{"error":"DB query"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cols []CollectionInfo
	for rows.Next() {
		var c CollectionInfo
		_ = rows.Scan(&c.ID, &c.Filename, &c.ImportedAt, &c.Hostname, &c.OSName,
			&c.Artifacts, &c.Status, &c.ReportPath)
		cols = append(cols, c)
	}
	if cols == nil {
		cols = []CollectionInfo{}
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(cols)
	w.Write(data)
}

func handleGetCollectionData(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"id manquant"}`, http.StatusBadRequest)
		return
	}
	dbMu.Lock()
	var filename string
	if db != nil {
		_ = db.QueryRow(`SELECT filename FROM collections WHERE id=?`, id).Scan(&filename)
	}
	dbMu.Unlock()

	if filename == "" {
		http.Error(w, `{"error":"collection introuvable"}`, http.StatusNotFound)
		return
	}

	parsed, err := parseVelociraptorZIP(filename)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(parsed)
	w.Write(data)
}
