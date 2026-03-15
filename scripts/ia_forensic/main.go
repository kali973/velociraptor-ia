// ia_forensic — IHM Web Velociraptor-IA
//
// 4 étapes :
//  1. PACKAGING  : sélection artefacts + lancement collecte Velociraptor
//  2. COLLECTION : import ZIP de collecte
//  3. ANALYSE IA : analyse forensique par Mistral 7B / Qwen2.5 14B
//  4. RAPPORT    : génération et téléchargement DOCX/JSON
//
// Build : go build -ldflags="-s -w" -o ia_forensic.exe .

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	currentCfg *Config
	cfgMu      sync.RWMutex
)

func main() {
	port := flag.String("port", "8767", "Port de l'interface web")
	dbDir := flag.String("dbdir", "../collections", "Dossier pour la base de données")
	flag.Parse()

	// Brancher le broadcaster de logs
	log.SetOutput(logWriter{})
	log.SetFlags(log.Ltime | log.Lmsgprefix)

	fmt.Println("+-------------------------------------------------------+")
	fmt.Println("|  Velociraptor-IA — IHM Forensique                     |")
	fmt.Println("|  Collecte ▸ Analyse IA ▸ Rapport DFIR                 |")
	fmt.Println("+-------------------------------------------------------+")

	cfg := loadConfig()
	if *port != "8767" {
		cfg.UIPort = *port
	}
	currentCfg = cfg

	if err := initDB(*dbDir); err != nil {
		log.Printf("[WARN] initDB : %v", err)
	}

	// Créer les dossiers nécessaires
	for _, d := range []string{cfg.OutputDir, cfg.ReportsDir} {
		_ = os.MkdirAll(d, 0755)
	}

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/config", handleConfig)

	// Étape 1 — Packaging / collecte
	mux.HandleFunc("/api/artifacts", handleListArtifacts)
	mux.HandleFunc("/api/collector/build", handleBuildCollectorHTTP)
	mux.HandleFunc("/api/collector/status", handleBuildStatusHTTP)
	mux.HandleFunc("/api/velociraptor/gui", handleLaunchVeloGUI)
	mux.HandleFunc("/api/velociraptor/detect", handleDetectVelo)
	mux.HandleFunc("/api/velociraptor/build", handleBuildVelociraptor)
	mux.HandleFunc("/api/velociraptor/build/status", handleBuildVeloStatus)

	// Étape 2 — Import collecte
	mux.HandleFunc("/api/collections", handleListCollections)
	mux.HandleFunc("/api/collections/upload", handleUploadCollection)
	mux.HandleFunc("/api/collections/data", handleGetCollectionData)

	// Étape 3 — Analyse IA
	mux.HandleFunc("/api/analysis/start", handleStartAnalysis)
	mux.HandleFunc("/api/analysis/status", handleAnalysisStatus)
	mux.HandleFunc("/api/analysis/result", handleGetAnalysis)

	// Étape 4 — Rapport
	mux.HandleFunc("/api/report/export", handleExportReport)

	// Logs SSE
	mux.HandleFunc("/api/logs/stream", handleLogsStream)

	addr := "http://localhost:" + cfg.UIPort
	go openBrowser(addr)

	fmt.Printf("\n[INFO] IHM démarrée sur %s\n", addr)
	fmt.Printf("[INFO] Logs en temps réel via le bouton 🔍\n\n")

	srv := &http.Server{
		Addr:    ":" + cfg.UIPort,
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}

// ─── Config handler ───────────────────────────────────────────────────────────

func handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		cfgMu.RLock()
		data, _ := json.Marshal(currentCfg)
		cfgMu.RUnlock()
		w.Write(data)
	case http.MethodPost:
		var newCfg Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, `{"error":"JSON invalide"}`, http.StatusBadRequest)
			return
		}
		if newCfg.UIPort == "" {
			newCfg.UIPort = "8767"
		}
		cfgMu.Lock()
		currentCfg = &newCfg
		cfgMu.Unlock()
		_ = saveConfigToDisk(&newCfg)
		w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, `{"error":"méthode non supportée"}`, http.StatusMethodNotAllowed)
	}
}

// ─── Artefacts ────────────────────────────────────────────────────────────────

func handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(ArtifactCatalog)
	w.Write(data)
}

// ─── Collector build HTTP handlers ───────────────────────────────────────────

func handleBuildCollectorHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST requis"}`, http.StatusMethodNotAllowed)
		return
	}
	var req CollectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"JSON invalide"}`, http.StatusBadRequest)
		return
	}
	if len(req.Artifacts) == 0 {
		http.Error(w, `{"error":"aucun artefact sélectionné"}`, http.StatusBadRequest)
		return
	}

	buildMu.Lock()
	if buildRunning {
		buildMu.Unlock()
		http.Error(w, `{"error":"build déjà en cours"}`, http.StatusConflict)
		return
	}
	buildRunning = true
	buildDone = false
	buildSuccess = false
	buildOutput = nil
	buildResult = ""
	buildMu.Unlock()

	cfgMu.RLock()
	cfg := *currentCfg
	cfgMu.RUnlock()

	go runBuildCollector(req, &cfg)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"msg":"collecte démarrée"}`))
}

func handleBuildStatusHTTP(w http.ResponseWriter, r *http.Request) {
	buildMu.Lock()
	data, _ := json.Marshal(map[string]interface{}{
		"running": buildRunning,
		"done":    buildDone,
		"success": buildSuccess,
		"result":  buildResult,
		"lines":   buildOutput,
	})
	buildMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// ─── Velociraptor GUI ─────────────────────────────────────────────────────────

func handleLaunchVeloGUI(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	cfg := *currentCfg
	cfgMu.RUnlock()

	bin := findVelociraptorBin(cfg.VeloRaptorBin)
	if bin == "" {
		http.Error(w, `{"error":"velociraptor.exe introuvable — compilez d'abord avec 'Compiler Velociraptor'"}`, http.StatusNotFound)
		return
	}

	log.Printf("[VELO] Lancement GUI : %s gui", bin)
	cmd := exec.Command(bin, "gui")
	if err := cmd.Start(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	go func() {
		time.Sleep(3 * time.Second)
		openBrowser("https://localhost:8889")
	}()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"url":"https://localhost:8889"}`))
}

func handleDetectVelo(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	cfg := *currentCfg
	cfgMu.RUnlock()

	bin := findVelociraptorBin(cfg.VeloRaptorBin)

	// Chercher le dossier output/ (créé par make windows)
	outputDir := ""
	for _, base := range []string{".", "..", "../.."} {
		p := filepath.Join(base, "output")
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			outputDir = abs
			break
		}
	}

	// Vérifier que make.go existe (projet compilable depuis les sources)
	makeGoExists := false
	for _, base := range []string{".", "..", "../.."} {
		if _, err := os.Stat(filepath.Join(base, "make.go")); err == nil {
			makeGoExists = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(map[string]interface{}{
		"found":          bin != "",
		"path":           bin,
		"output_dir":     outputDir,
		"make_go_exists": makeGoExists,
		"build_cmd":      "go run make.go -v windowsDev",
	})
	w.Write(data)
}

// ─── Build Velociraptor depuis les sources ────────────────────────────────────

var (
	veloBuildMu      sync.Mutex
	veloBuildRunning bool
	veloBuildDone    bool
	veloBuildSuccess bool
	veloBuildLines   []string
	veloBuildResult  string
)

func handleBuildVelociraptor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST requis"}`, http.StatusMethodNotAllowed)
		return
	}

	veloBuildMu.Lock()
	if veloBuildRunning {
		veloBuildMu.Unlock()
		http.Error(w, `{"error":"build déjà en cours"}`, http.StatusConflict)
		return
	}
	veloBuildRunning = true
	veloBuildDone = false
	veloBuildSuccess = false
	veloBuildLines = nil
	veloBuildResult = ""
	veloBuildMu.Unlock()

	go runBuildVelociraptor()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"msg":"Compilation de velociraptor.exe démarrée (10-15 min)..."}`))
}

func handleBuildVeloStatus(w http.ResponseWriter, r *http.Request) {
	veloBuildMu.Lock()
	data, _ := json.Marshal(map[string]interface{}{
		"running": veloBuildRunning,
		"done":    veloBuildDone,
		"success": veloBuildSuccess,
		"result":  veloBuildResult,
		"lines":   veloBuildLines,
	})
	veloBuildMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func runBuildVelociraptor() {
	defer func() {
		veloBuildMu.Lock()
		veloBuildRunning = false
		veloBuildDone = true
		veloBuildMu.Unlock()
	}()

	addLine := func(msg string) {
		log.Printf("[BUILD-VELO] %s", msg)
		veloBuildMu.Lock()
		veloBuildLines = append(veloBuildLines, msg)
		veloBuildMu.Unlock()
	}

	// Trouver la racine du projet (là où se trouve make.go)
	projectRoot := ""
	for _, base := range []string{".", "..", "../.."} {
		if _, err := os.Stat(filepath.Join(base, "make.go")); err == nil {
			abs, _ := filepath.Abs(base)
			projectRoot = abs
			break
		}
	}

	if projectRoot == "" {
		addLine("ERREUR : make.go introuvable. Assurez-vous que ia_forensic/ est bien dans scripts/ du projet velociraptor-ia.")
		veloBuildMu.Lock()
		veloBuildSuccess = false
		veloBuildMu.Unlock()
		return
	}

	addLine(fmt.Sprintf("Racine projet : %s", projectRoot))

	// Vérifier les prérequis
	addLine("Vérification des prérequis...")

	// Go
	if _, err := exec.LookPath("go"); err != nil {
		addLine("ERREUR : 'go' introuvable dans le PATH. Installez Go >= 1.23 depuis https://golang.org/dl/")
		veloBuildMu.Lock()
		veloBuildSuccess = false
		veloBuildMu.Unlock()
		return
	}
	out, _ := exec.Command("go", "version").Output()
	addLine("Go : " + strings.TrimSpace(string(out)))

	// GCC (requis par CGO)
	if _, err := exec.LookPath("gcc"); err != nil {
		addLine("ERREUR : GCC introuvable. Installez TDM-GCC depuis https://jmeubank.github.io/tdm-gcc/ et ajoutez-le au PATH.")
		veloBuildMu.Lock()
		veloBuildSuccess = false
		veloBuildMu.Unlock()
		return
	}
	gccOut, _ := exec.Command("gcc", "--version").Output()
	firstLine := strings.Split(strings.TrimSpace(string(gccOut)), "\n")[0]
	addLine("GCC : " + firstLine)

	// Vérifier si Node.js est disponible pour la GUI (non bloquant)
	if _, err := exec.LookPath("node"); err != nil {
		addLine("AVERTISSEMENT : Node.js absent — la GUI Velociraptor ne sera pas incluse (fonctionnement CLI OK)")
	} else {
		nodeOut, _ := exec.Command("node", "--version").Output()
		addLine("Node.js : " + strings.TrimSpace(string(nodeOut)))
	}

	// go mod download (télécharger les dépendances)
	addLine("Téléchargement des dépendances Go...")
	modCmd := exec.Command("go", "mod", "download")
	modCmd.Dir = projectRoot
	var modOut bytes.Buffer
	modCmd.Stdout = &modOut
	modCmd.Stderr = &modOut
	if err := modCmd.Run(); err != nil {
		addLine("AVERTISSEMENT go mod download : " + strings.TrimSpace(modOut.String()))
	} else {
		addLine("Dépendances OK")
	}

	// Lancer : go run make.go -v windowsDev
	addLine("Lancement : go run make.go -v windowsDev")
	addLine("(cela peut prendre 10-15 minutes selon votre machine)")

	buildCmd := exec.Command("go", "run", "make.go", "-v", "windowsDev")
	buildCmd.Dir = projectRoot

	// Capturer la sortie ligne par ligne
	buildCmd.Stdout = &lineWriter{fn: addLine}
	buildCmd.Stderr = &lineWriter{fn: addLine}

	if err := buildCmd.Run(); err != nil {
		addLine(fmt.Sprintf("ERREUR : go run make.go a échoué : %v", err))
		veloBuildMu.Lock()
		veloBuildSuccess = false
		veloBuildMu.Unlock()
		return
	}

	// Chercher le binaire produit dans output/
	bin := findVelociraptorBin("")
	if bin == "" {
		addLine("Build terminé mais velociraptor.exe introuvable dans output/. Vérifiez le dossier output/ manuellement.")
		veloBuildMu.Lock()
		veloBuildSuccess = false
		veloBuildMu.Unlock()
		return
	}

	addLine(fmt.Sprintf("✓ velociraptor.exe compilé : %s", bin))
	veloBuildMu.Lock()
	veloBuildSuccess = true
	veloBuildResult = bin
	veloBuildMu.Unlock()
}

// lineWriter permet de capturer la sortie d'une commande ligne par ligne.
type lineWriter struct {
	fn  func(string)
	buf []byte
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	lw.buf = append(lw.buf, p...)
	for {
		idx := strings.IndexByte(string(lw.buf), '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(string(lw.buf[:idx]), "\r")
		if line != "" {
			lw.fn(line)
		}
		lw.buf = lw.buf[idx+1:]
	}
	return len(p), nil
}

// ─── Analyse IA HTTP handlers ─────────────────────────────────────────────────

func handleStartAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST requis"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CollectionID string `json:"collection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"JSON invalide"}`, http.StatusBadRequest)
		return
	}
	if req.CollectionID == "" {
		http.Error(w, `{"error":"collection_id manquant"}`, http.StatusBadRequest)
		return
	}

	analysisMu.Lock()
	if analysisRunning {
		analysisMu.Unlock()
		http.Error(w, `{"error":"analyse déjà en cours"}`, http.StatusConflict)
		return
	}
	analysisRunning = true
	analysisDone = false
	analysisResult = nil
	analysisErr = ""
	analysisMu.Unlock()

	// Récupérer le chemin du fichier ZIP
	dbMu.Lock()
	var zipPath string
	if db != nil {
		_ = db.QueryRow(`SELECT filename FROM collections WHERE id=?`, req.CollectionID).Scan(&zipPath)
	}
	dbMu.Unlock()

	if zipPath == "" {
		analysisMu.Lock()
		analysisRunning = false
		analysisMu.Unlock()
		http.Error(w, `{"error":"collection introuvable"}`, http.StatusNotFound)
		return
	}

	cfgMu.RLock()
	cfg := *currentCfg
	cfgMu.RUnlock()

	log.Printf("[IA] Démarrage analyse : %s", req.CollectionID)
	go runAnalysis(req.CollectionID, zipPath, &cfg)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"msg":"analyse démarrée"}`))
}

func handleAnalysisStatus(w http.ResponseWriter, r *http.Request) {
	analysisMu.Lock()
	data, _ := json.Marshal(map[string]interface{}{
		"running":    analysisRunning,
		"done":       analysisDone,
		"error":      analysisErr,
		"has_result": analysisResult != nil,
	})
	analysisMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// ─── SSE Logs ─────────────────────────────────────────────────────────────────

func handleLogsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	for _, line := range logHub.getHistory() {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	flusher.Flush()

	ch := logHub.subscribe()
	defer logHub.unsubscribe(ch)

	ctx := r.Context()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// ─── Browser ──────────────────────────────────────────────────────────────────

func openBrowser(addr string) {
	time.Sleep(800 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", addr)
	case "darwin":
		cmd = exec.Command("open", addr)
	default:
		cmd = exec.Command("xdg-open", addr)
	}
	_ = cmd.Start()
}

// ─── IHM HTML ─────────────────────────────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Velociraptor-IA — Forensique DFIR</title>
<link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#030a14;--bg2:#071020;--card:#0b1929;--card2:#0e1f34;
  --blue:#00b4ff;--cyan:#00e5ff;--green:#00ff9d;--yellow:#ffb830;
  --warn:#f59e0b;--red:#ff4466;--danger:#ef4444;--purple:#b04fff;
  --text:#c8daf0;--muted:#5a7a9a;--border:rgba(0,180,255,0.12);
  --font-ui:'Exo 2',sans-serif;--font-mono:'JetBrains Mono',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:14px;min-height:100vh}

/* ── Header ── */
header{
  background:linear-gradient(135deg,#040e1c,#071826);
  border-bottom:1px solid var(--border);padding:0 24px;height:58px;
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:200;
}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{
  width:38px;height:38px;background:linear-gradient(135deg,var(--blue),var(--cyan));
  border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:22px;
}
.logo-title{font-size:17px;font-weight:700;color:var(--text)}
.logo-sub{font-size:11px;color:var(--muted);font-family:var(--font-mono)}
.hdr-right{display:flex;align-items:center;gap:10px}
.badge{background:rgba(0,180,255,0.1);border:1px solid rgba(0,180,255,0.3);
  color:var(--blue);padding:4px 11px;border-radius:20px;font-size:11px;font-weight:600;font-family:var(--font-mono)}
.btn-log{
  background:transparent;border:1px solid var(--border);color:var(--muted);
  width:36px;height:36px;border-radius:8px;font-size:17px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:.2s;
}
.btn-log:hover,.btn-log.active{border-color:var(--blue);color:var(--blue);background:rgba(0,180,255,0.08)}

/* ── Stepper ── */
.stepper{
  display:flex;align-items:center;justify-content:center;gap:0;
  padding:18px 24px 0;max-width:1100px;margin:0 auto;
}
.step{
  display:flex;flex-direction:column;align-items:center;gap:6px;
  flex:1;cursor:pointer;padding:12px 8px;border-radius:10px;
  border:1px solid transparent;transition:.2s;position:relative;
}
.step:hover{background:rgba(0,180,255,0.04);border-color:var(--border)}
.step.active{background:rgba(0,180,255,0.08);border-color:rgba(0,180,255,0.3)}
.step.done .step-num{background:var(--green);color:#000}
.step-num{
  width:34px;height:34px;border-radius:50%;
  background:var(--card2);border:2px solid var(--border);
  display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:700;color:var(--muted);transition:.2s;
}
.step.active .step-num{background:var(--blue);color:#fff;border-color:var(--blue)}
.step-label{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;text-align:center}
.step.active .step-label{color:var(--blue)}
.step-icon{font-size:18px}
.step-conn{width:40px;height:2px;background:var(--border);flex-shrink:0}

/* ── Layout ── */
.main{max-width:1100px;margin:0 auto;padding:24px 24px 60px}

/* ── Panel ── */
.panel{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  overflow:hidden;margin-bottom:20px;display:none;
}
.panel.active{display:block}
.panel-hdr{
  background:linear-gradient(90deg,var(--card2),rgba(0,180,255,0.04));
  border-bottom:1px solid var(--border);padding:14px 20px;
  display:flex;align-items:center;gap:12px;
}
.panel-hdr h2{font-size:14px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.8px}
.panel-hdr .step-badge{
  background:var(--blue);color:#fff;font-size:11px;font-weight:700;
  padding:2px 8px;border-radius:10px;
}
.panel-body{padding:20px}

/* ── Artefact grid ── */
.art-groups{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;margin-bottom:20px}
.art-group{
  background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:14px;
}
.art-group-hdr{
  display:flex;align-items:center;gap:8px;margin-bottom:10px;
  font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.6px;
  cursor:pointer;
}
.art-group-check{accent-color:var(--blue)}
.art-item{display:flex;align-items:center;gap:8px;padding:3px 0}
.art-item input{accent-color:var(--blue)}
.art-item label{font-family:var(--font-mono);font-size:11px;color:var(--muted);cursor:pointer}
.art-item label:hover{color:var(--text)}

/* ── Collections list ── */
.col-list{display:flex;flex-direction:column;gap:10px}
.col-card{
  background:var(--bg2);border:1px solid var(--border);border-radius:9px;
  padding:14px 16px;display:flex;align-items:center;justify-content:space-between;
  cursor:pointer;transition:.2s;
}
.col-card:hover{border-color:rgba(0,180,255,0.3)}
.col-card.selected{border-color:var(--blue);background:rgba(0,180,255,0.06)}
.col-info{flex:1}
.col-hostname{font-weight:700;color:var(--text);font-size:14px}
.col-meta{font-size:11px;color:var(--muted);margin-top:3px;font-family:var(--font-mono)}
.col-status{font-size:11px;padding:3px 9px;border-radius:12px;font-weight:600}
.col-status.imported{background:rgba(0,180,255,0.1);color:var(--blue)}
.col-status.analysed{background:rgba(0,255,157,0.1);color:var(--green)}

/* ── Analysis result ── */
.report-section{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:16px;margin-bottom:14px}
.report-section h3{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px}
.threat-badge{
  display:inline-block;padding:6px 16px;border-radius:8px;font-weight:700;
  font-size:16px;letter-spacing:1px;margin-bottom:12px;
}
.threat-CRITIQUE{background:rgba(239,68,68,.15);color:#ef4444}
.threat-ELEVE{background:rgba(245,158,11,.15);color:#f59e0b}
.threat-MOYEN{background:rgba(234,179,8,.15);color:#eab308}
.threat-FAIBLE{background:rgba(34,197,94,.15);color:#22c55e}
.threat-BENIN{background:rgba(107,114,128,.15);color:#9ca3af}
.finding-item{
  padding:7px 10px;margin-bottom:5px;border-radius:6px;
  background:rgba(0,0,0,.2);border-left:3px solid var(--blue);
  font-size:12.5px;color:var(--text);
}
.ioc-row{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(0,180,255,.06)}
.ioc-type{
  font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;
  background:rgba(0,180,255,.1);color:var(--blue);font-family:var(--font-mono);
  flex-shrink:0;
}
.mitre-pill{
  display:inline-block;background:rgba(176,79,255,.15);color:#b04fff;
  border-radius:5px;padding:3px 8px;font-size:11px;font-family:var(--font-mono);
  margin:3px;
}
.timeline-item{display:flex;gap:12px;padding:7px 0;border-bottom:1px solid rgba(0,180,255,.06)}
.timeline-time{font-family:var(--font-mono);font-size:11px;color:var(--blue);flex-shrink:0;width:55px}
.timeline-evt{font-size:12px;color:var(--text)}
.timeline-src{font-size:10px;color:var(--muted);font-family:var(--font-mono)}

/* ── Formulaires ── */
.form-row{margin-bottom:14px}
label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:600;display:block;margin-bottom:5px}
input[type="text"],input[type="password"],select{
  width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:7px;
  padding:9px 12px;color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none;
}
input:focus,select:focus{border-color:var(--blue)}

/* ── Boutons ── */
.btn{padding:9px 18px;border-radius:8px;border:none;cursor:pointer;font-family:var(--font-ui);font-weight:600;font-size:13px;transition:.2s}
.btn-primary{background:linear-gradient(135deg,var(--blue),#0090d4);color:#fff}
.btn-primary:hover{opacity:.88}
.btn-primary:disabled{opacity:.45;cursor:not-allowed}
.btn-success{background:linear-gradient(135deg,var(--green),#00c870);color:#000}
.btn-success:hover{opacity:.88}
.btn-success:disabled{opacity:.45;cursor:not-allowed}
.btn-danger{background:linear-gradient(135deg,var(--red),#cc0033);color:#fff}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--muted)}
.btn-ghost:hover{border-color:var(--blue);color:var(--blue)}
.btn-purple{background:linear-gradient(135deg,#7c3aed,#5b21b6);color:#fff}
.btn-purple:hover{opacity:.88}
.btn-purple:disabled{opacity:.45;cursor:not-allowed}
.btn-row{display:flex;gap:10px;flex-wrap:wrap}

/* ── Progress ── */
.progress-wrap{display:none;flex-direction:column;gap:7px;margin:14px 0}
.progress-wrap.visible{display:flex}
.progress-track{height:6px;background:var(--bg2);border-radius:3px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:3px;transition:width .3s;width:0%}
.progress-label{font-size:12px;color:var(--muted);font-family:var(--font-mono)}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Drop zone ── */
.dropzone{
  border:2px dashed var(--border);border-radius:10px;padding:40px 20px;text-align:center;
  cursor:pointer;transition:.2s;margin-bottom:16px;
}
.dropzone:hover,.dropzone.drag{border-color:var(--blue);background:rgba(0,180,255,.04)}
.dropzone-icon{font-size:36px;margin-bottom:10px}
.dropzone-label{font-size:14px;color:var(--text);font-weight:600;margin-bottom:6px}
.dropzone-sub{font-size:12px;color:var(--muted)}

/* ── Log window ── */
#logWindow{
  position:fixed;bottom:24px;right:24px;width:700px;height:340px;
  background:rgba(3,10,20,.97);border:1px solid rgba(0,180,255,.28);border-radius:12px;
  box-shadow:0 8px 40px rgba(0,0,0,.75);display:none;flex-direction:column;
  z-index:9999;overflow:hidden;min-width:320px;min-height:140px;backdrop-filter:blur(10px);
}
#logWindow.open{display:flex}
.log-titlebar{
  background:linear-gradient(90deg,#040e1c,rgba(0,180,255,.06));
  border-bottom:1px solid rgba(0,180,255,.15);
  padding:8px 14px;display:flex;align-items:center;justify-content:space-between;
  cursor:grab;user-select:none;flex-shrink:0;
}
.log-titlebar:active{cursor:grabbing}
.log-title{font-size:11px;font-weight:700;color:var(--blue);letter-spacing:1px;text-transform:uppercase;display:flex;align-items:center;gap:8px}
.log-dot{width:7px;height:7px;border-radius:50%;background:var(--blue);animation:lpulse 1.8s infinite}
@keyframes lpulse{0%,100%{opacity:1}50%{opacity:.3}}
.log-close{cursor:pointer;color:var(--muted);font-size:15px;padding:2px 5px;border-radius:4px}
.log-close:hover{color:var(--red);background:rgba(255,68,102,.12)}
#logContent{flex:1;overflow-y:auto;padding:9px 13px;font-family:var(--font-mono);font-size:11.5px;line-height:1.65}
.log-line{white-space:pre-wrap;word-break:break-all;padding:1px 0}
.log-line.lcollector{color:#00b4ff}
.log-line.lia{color:#00ff9d}
.log-line.lrapport{color:#b04fff}
.log-line.lwarn{color:#f59e0b}
.log-line.lerror{color:#ff4466}
.log-line.linfo{color:#8da9c4}
.log-resize{position:absolute;bottom:0;right:0;width:18px;height:18px;cursor:se-resize;background:linear-gradient(135deg,transparent 50%,rgba(0,180,255,.4) 50%);border-radius:0 0 12px 0}

/* ── Velo detect badge ── */
.velo-status{display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px}
.velo-ok{background:rgba(0,255,157,.08);border:1px solid rgba(0,255,157,.2);color:var(--green)}
.velo-missing{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444}

::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
@media(max-width:800px){.art-groups{grid-template-columns:1fr}}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🦖</div>
    <div>
      <div class="logo-title">Velociraptor-IA</div>
      <div class="logo-sub">Forensique DFIR • Analyse IA locale</div>
    </div>
  </div>
  <div class="hdr-right">
    <div class="badge">DFIR PLATFORM</div>
    <button class="btn-log" id="logBtn" onclick="toggleLog()" title="Logs temps réel">🔍</button>
  </div>
</header>

<!-- Fenêtre logs flottante -->
<div id="logWindow">
  <div class="log-titlebar" id="logBar">
    <div class="log-title">
      <div class="log-dot"></div>
      <span>Logs serveur</span>
      <span id="logCnt" style="font-size:10px;color:var(--muted)"></span>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <span style="font-size:10px;color:var(--muted);cursor:pointer" onclick="clearLogs()">🗑</span>
      <span class="log-close" onclick="toggleLog()">✕</span>
    </div>
  </div>
  <div id="logContent"></div>
  <div class="log-resize" id="logResize"></div>
</div>

<!-- Stepper -->
<div class="stepper" id="stepper">
  <div class="step active" id="step-tab-1" onclick="goStep(1)">
    <div class="step-icon">📦</div>
    <div class="step-num" id="snum1">1</div>
    <div class="step-label">Collecte</div>
  </div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-2" onclick="goStep(2)">
    <div class="step-icon">📂</div>
    <div class="step-num" id="snum2">2</div>
    <div class="step-label">Import</div>
  </div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-3" onclick="goStep(3)">
    <div class="step-icon">🧠</div>
    <div class="step-num" id="snum3">3</div>
    <div class="step-label">Analyse IA</div>
  </div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-4" onclick="goStep(4)">
    <div class="step-icon">📄</div>
    <div class="step-num" id="snum4">4</div>
    <div class="step-label">Rapport</div>
  </div>
</div>

<div class="main">

<!-- ═══════════════════════════════════════════════════════════════════════════
     ÉTAPE 1 — COLLECTE
═══════════════════════════════════════════════════════════════════════════ -->
<div class="panel active" id="panel1">
  <div class="panel-hdr">
    <span>📦</span>
    <h2>Étape 1 — Packaging & Collecte Velociraptor</h2>
    <span class="step-badge">1/4</span>
  </div>
  <div class="panel-body">

    <!-- Statut Velociraptor -->
    <div id="veloStatusPanel" style="border-radius:9px;padding:14px 16px;margin-bottom:16px;border:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <span id="veloIcon" style="font-size:22px">⏳</span>
        <div>
          <div id="veloTitle" style="font-weight:700;color:var(--text);font-size:14px">Détection de Velociraptor...</div>
          <div id="veloPath" style="font-size:11px;color:var(--muted);font-family:var(--font-mono)"></div>
        </div>
        <button class="btn btn-ghost" style="margin-left:auto;padding:5px 12px;font-size:11px" onclick="detectVelo()">🔄 Détecter</button>
      </div>

      <!-- Panneau BUILD (visible si pas trouvé) -->
      <div id="veloBuildPanel" style="display:none;background:rgba(0,0,0,.2);border-radius:8px;padding:14px;border-left:3px solid var(--yellow)">
        <div style="font-size:12.5px;font-weight:700;color:var(--yellow);margin-bottom:8px">📦 Compiler Velociraptor depuis les sources</div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px">
          Le projet <code style="color:var(--blue)">velociraptor-ia</code> est un fork du code source Velociraptor.<br>
          La commande <code style="color:var(--green)">go run make.go -v windowsDev</code> compile <code style="color:var(--cyan)">output/velociraptor-vX.X.X-windows-amd64.exe</code>.<br>
          <strong style="color:var(--warn)">Prérequis :</strong> Go ≥ 1.23 · GCC (TDM-GCC) · Node.js (pour la GUI)
        </div>
        <div class="progress-wrap" id="veloBuildProgress">
          <div style="display:flex;align-items:center;gap:8px">
            <div class="spinner"></div>
            <span id="veloBuildMsg" style="font-size:12px;color:var(--muted)">Compilation en cours (10-15 min)...</span>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-success" id="btnBuildVelo" onclick="buildVelociraptor()">🔨 Compiler velociraptor.exe</button>
          <a href="https://github.com/Velocidex/velociraptor/releases" target="_blank" class="btn btn-ghost">⬇ Télécharger le binaire (GitHub)</a>
        </div>
        <div id="veloBuildOut" style="margin-top:10px;font-family:var(--font-mono);font-size:10.5px;color:var(--muted);max-height:120px;overflow-y:auto;display:none"></div>
      </div>

      <!-- Panneau PRÊT (visible si trouvé) -->
      <div id="veloReadyPanel" style="display:none">
        <div class="btn-row">
          <button class="btn btn-primary" onclick="launchVeloGUI()">🦖 Ouvrir Velociraptor GUI</button>
        </div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px" id="collectOptions">
      <div class="form-row">
        <label>Chemin velociraptor.exe (optionnel)</label>
        <input type="text" id="veloPath2" placeholder="Auto-détecté dans output/">
      </div>
      <div class="form-row">
        <label>OS cible de la collecte</label>
        <select id="targetOS">
          <option value="windows" selected>Windows (amd64)</option>
          <option value="linux">Linux (amd64)</option>
          <option value="darwin">macOS</option>
        </select>
      </div>
    </div>

    <div style="margin-bottom:14px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <label style="margin:0">Artefacts à collecter</label>
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="selectAllArtifacts(true)">Tout sélectionner</button>
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="selectAllArtifacts(false)">Tout désélectionner</button>
        </div>
      </div>
      <div class="art-groups" id="artGroups">
        <div style="color:var(--muted);font-size:13px">Chargement des artefacts...</div>
      </div>
    </div>

    <!-- Progress build -->
    <div class="progress-wrap" id="buildProgress">
      <div style="display:flex;align-items:center;gap:8px">
        <div class="spinner"></div>
        <span id="buildMsg" style="font-size:13px;color:var(--muted)">Collecte en cours...</span>
      </div>
    </div>

    <div class="btn-row">
      <button class="btn btn-success" id="btnCollect" onclick="startCollect()">▶ Lancer la collecte</button>
      <button class="btn btn-primary" onclick="launchVeloGUI()">🦖 Ouvrir Velociraptor GUI</button>
      <button class="btn btn-ghost" onclick="goStep(2)">Passer à l'import →</button>
    </div>

  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════════
     ÉTAPE 2 — IMPORT COLLECTION
═══════════════════════════════════════════════════════════════════════════ -->
<div class="panel" id="panel2">
  <div class="panel-hdr">
    <span>📂</span>
    <h2>Étape 2 — Import de la collecte</h2>
    <span class="step-badge">2/4</span>
  </div>
  <div class="panel-body">

    <div class="dropzone" id="dropzone"
      ondragover="event.preventDefault();this.classList.add('drag')"
      ondragleave="this.classList.remove('drag')"
      ondrop="handleDrop(event)"
      onclick="document.getElementById('fileInput').click()">
      <div class="dropzone-icon">📦</div>
      <div class="dropzone-label">Glissez le ZIP de collecte ici</div>
      <div class="dropzone-sub">ou cliquez pour sélectionner le fichier</div>
      <div id="dropInfo" style="margin-top:10px;font-size:12px;color:var(--blue)"></div>
    </div>
    <input type="file" id="fileInput" style="display:none" accept=".zip,.tar.gz"
      onchange="uploadCollection(this.files[0])">

    <div class="progress-wrap" id="uploadProgress">
      <div style="display:flex;align-items:center;gap:8px">
        <div class="spinner"></div>
        <span style="font-size:13px;color:var(--muted)">Import en cours...</span>
      </div>
    </div>

    <div id="colList" class="col-list" style="margin-top:16px">
      <div style="color:var(--muted);font-size:13px;text-align:center;padding:20px">
        Aucune collection importée
      </div>
    </div>

    <div class="btn-row" style="margin-top:16px">
      <button class="btn btn-ghost" onclick="goStep(1)">← Retour</button>
      <button class="btn btn-primary" id="btnToAnalysis" disabled onclick="goStep(3)">Analyser →</button>
    </div>

  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════════
     ÉTAPE 3 — ANALYSE IA
═══════════════════════════════════════════════════════════════════════════ -->
<div class="panel" id="panel3">
  <div class="panel-hdr">
    <span>🧠</span>
    <h2>Étape 3 — Analyse forensique IA</h2>
    <span class="step-badge">3/4</span>
  </div>
  <div class="panel-body">

    <div id="selectedColInfo" style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px">
      <div style="color:var(--muted);font-size:13px">Aucune collection sélectionnée</div>
    </div>

    <div style="background:rgba(0,255,157,.06);border:1px solid rgba(0,255,157,.2);border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:12.5px;color:var(--green)">
      <strong>🤖 Moteur IA local</strong> — Mistral 7B (priorité) ou Qwen2.5 14B<br>
      <span style="color:var(--muted);font-size:11px">Le moteur est démarré automatiquement depuis <code>../moteur/llama-server.exe</code></span>
    </div>

    <div class="progress-wrap" id="analysisProgress">
      <div style="display:flex;align-items:center;gap:8px">
        <div class="spinner"></div>
        <span id="analysisMsg" style="font-size:13px;color:var(--muted)">Initialisation du moteur IA...</span>
      </div>
      <div class="progress-track"><div class="progress-fill" id="analysisFill" style="width:30%"></div></div>
    </div>

    <!-- Résultats IA -->
    <div id="analysisResult" style="display:none">

      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
        <div id="threatBadge" class="threat-badge">—</div>
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text)" id="compromisedStatus">—</div>
          <div style="font-size:11px;color:var(--muted)" id="engineName">—</div>
        </div>
      </div>

      <div class="report-section">
        <h3>Résumé exécutif</h3>
        <p id="execSummary" style="font-size:13px;color:var(--text);line-height:1.7"></p>
      </div>

      <div class="report-section">
        <h3>Découvertes clés</h3>
        <div id="keyFindings"></div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="report-section">
          <h3>Processus suspects</h3>
          <div id="suspProcs"></div>
        </div>
        <div class="report-section">
          <h3>Trafic réseau suspect</h3>
          <div id="suspNet"></div>
        </div>
      </div>

      <div class="report-section">
        <h3>Mécanismes de persistance</h3>
        <div id="persistMechs"></div>
      </div>

      <div class="report-section">
        <h3>Indicateurs de compromission (IOCs)</h3>
        <div id="iocList"></div>
      </div>

      <div class="report-section">
        <h3>Techniques MITRE ATT&CK</h3>
        <div id="mitreList"></div>
      </div>

      <div class="report-section">
        <h3>Timeline de l'attaque</h3>
        <div id="timeline"></div>
      </div>

      <div class="report-section">
        <h3>Recommandations SOC</h3>
        <div id="recommendations"></div>
      </div>
    </div>

    <div class="btn-row" style="margin-top:16px">
      <button class="btn btn-ghost" onclick="goStep(2)">← Retour</button>
      <button class="btn btn-primary" id="btnStartAnalysis" onclick="startAnalysis()">🧠 Lancer l'analyse IA</button>
      <button class="btn btn-ghost" id="btnToReport" disabled onclick="goStep(4)">Générer rapport →</button>
    </div>

  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════════
     ÉTAPE 4 — RAPPORT
═══════════════════════════════════════════════════════════════════════════ -->
<div class="panel" id="panel4">
  <div class="panel-hdr">
    <span>📄</span>
    <h2>Étape 4 — Rapport DFIR</h2>
    <span class="step-badge">4/4</span>
  </div>
  <div class="panel-body">

    <div id="reportSummary" style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px">
      <div style="color:var(--muted);font-size:13px">Aucune analyse disponible</div>
    </div>

    <div style="background:rgba(176,79,255,.06);border:1px solid rgba(176,79,255,.2);border-radius:8px;padding:14px;margin-bottom:16px">
      <div style="font-size:13px;font-weight:600;color:#b04fff;margin-bottom:6px">📄 Format du rapport</div>
      <div style="font-size:12px;color:var(--muted)">
        <strong style="color:var(--text)">DOCX</strong> si <code>docx_gen.js</code> + Node.js sont présents<br>
        <strong style="color:var(--text)">JSON structuré</strong> sinon (ouvrable dans tout éditeur)
      </div>
    </div>

    <div class="btn-row">
      <button class="btn btn-ghost" onclick="goStep(3)">← Retour</button>
      <button class="btn btn-purple" id="btnDownload" onclick="downloadReport()">⬇ Télécharger le rapport</button>
      <button class="btn btn-ghost" onclick="startOver()">🔄 Nouvelle analyse</button>
    </div>

  </div>
</div>

</div><!-- .main -->

<script>
'use strict';

// ── État global ──────────────────────────────────────────────────────────────
let currentStep = 1;
let selectedCollectionId = null;
let selectedCollectionInfo = null;
let analysisData = null;
let buildPollTimer = null;
let analysisPollTimer = null;

// ── Stepper ──────────────────────────────────────────────────────────────────
function goStep(n) {
  currentStep = n;
  for (let i = 1; i <= 4; i++) {
    const tab  = document.getElementById('step-tab-' + i);
    const panel = document.getElementById('panel' + i);
    const snum  = document.getElementById('snum' + i);
    tab.classList.toggle('active', i === n);
    panel.classList.toggle('active', i === n);
    if (i < n) tab.classList.add('done');
    else if (i > n) tab.classList.remove('done');
  }
  if (n === 2) loadCollections();
  if (n === 3) refreshSelectedCol();
  if (n === 4) refreshReportSummary();
}

// ── ÉTAPE 1 : Collecte ───────────────────────────────────────────────────────
async function detectVelo() {
  const r = await fetch('/api/velociraptor/detect');
  const d = await r.json();

  const panel     = document.getElementById('veloStatusPanel');
  const buildPanel = document.getElementById('veloBuildPanel');
  const readyPanel = document.getElementById('veloReadyPanel');
  const icon      = document.getElementById('veloIcon');
  const title     = document.getElementById('veloTitle');
  const pathEl    = document.getElementById('veloPath');
  const btnCollect = document.getElementById('btnCollect');

  if (d.found) {
    panel.style.background = 'rgba(0,255,157,.05)';
    panel.style.borderColor = 'rgba(0,255,157,.25)';
    icon.textContent = '\u2705';
    title.textContent = 'Velociraptor prêt';
    title.style.color = 'var(--green)';
    pathEl.textContent = d.path;
    buildPanel.style.display = 'none';
    readyPanel.style.display = 'block';
    btnCollect.disabled = false;
  } else {
    panel.style.background = 'rgba(255,180,0,.04)';
    panel.style.borderColor = 'rgba(255,180,0,.25)';
    icon.textContent = '\u26a0\ufe0f';
    title.textContent = 'Velociraptor non trouvé — compilation ou téléchargement requis';
    title.style.color = 'var(--yellow)';
    pathEl.textContent = d.make_go_exists
      ? 'make.go détecté — compilation possible avec go run make.go -v windowsDev'
      : 'Racine du projet non trouvée';
    buildPanel.style.display = 'block';
    readyPanel.style.display = 'none';
    btnCollect.disabled = true;
  }
}

async function loadArtifacts() {
  const r = await fetch('/api/artifacts');
  const groups = await r.json();
  const container = document.getElementById('artGroups');
  container.innerHTML = '';
  for (const grp of groups) {
    const div = document.createElement('div');
    div.className = 'art-group';
    div.innerHTML =
      '<div class="art-group-hdr">' +
        '<input type="checkbox" class="art-group-check" id="grp_' + grp.name + '"' +
          ' onchange="toggleGroup(\'' + grp.name + '\',this.checked)">' +
        '<span>' + grp.icon + '</span>' +
        '<label for="grp_' + grp.name + '" style="cursor:pointer">' + grp.label + '</label>' +
      '</div>' +
      grp.artifacts.map(a =>
        '<div class="art-item">' +
          '<input type="checkbox" id="art_' + a.replace(/\./g,'_') + '" value="' + a + '" class="art-cb" data-group="' + grp.name + '">' +
          '<label for="art_' + a.replace(/\./g,'_') + '">' + a + '</label>' +
        '</div>'
      ).join('');
    container.appendChild(div);
  }
}

function toggleGroup(grpName, checked) {
  document.querySelectorAll('[data-group="' + grpName + '"]').forEach(cb => {
    cb.checked = checked;
  });
}

function selectAllArtifacts(sel) {
  document.querySelectorAll('.art-cb').forEach(cb => cb.checked = sel);
  document.querySelectorAll('.art-group-check').forEach(cb => cb.checked = sel);
}

function getSelectedArtifacts() {
  return Array.from(document.querySelectorAll('.art-cb:checked')).map(cb => cb.value);
}

async function buildVelociraptor() {
  const btn = document.getElementById('btnBuildVelo');
  btn.disabled = true;
  document.getElementById('veloBuildProgress').classList.add('visible');
  document.getElementById('veloBuildOut').style.display = 'block';
  document.getElementById('veloBuildOut').textContent = '';
  document.getElementById('veloBuildMsg').textContent = 'Démarrage de la compilation...';

  const r = await fetch('/api/velociraptor/build', {method: 'POST'});
  const d = await r.json();
  if (!d.ok) {
    showToast('Erreur : ' + d.error, 'error');
    btn.disabled = false;
    document.getElementById('veloBuildProgress').classList.remove('visible');
    return;
  }

  // Polling du statut
  let veloBuildPoll = setInterval(async () => {
    const sr = await fetch('/api/velociraptor/build/status');
    const sd = await sr.json();

    if (sd.lines && sd.lines.length) {
      const out = document.getElementById('veloBuildOut');
      out.textContent = sd.lines.join('\n');
      out.scrollTop = out.scrollHeight;
      document.getElementById('veloBuildMsg').textContent = sd.lines[sd.lines.length - 1].slice(0, 80);
    }

    if (sd.done) {
      clearInterval(veloBuildPoll);
      btn.disabled = false;
      document.getElementById('veloBuildProgress').classList.remove('visible');

      if (sd.success) {
        showToast('Velociraptor compilé : ' + sd.result, 'success');
        detectVelo(); // Rafraîchir le statut
      } else {
        showToast('Compilation échouée — vérifiez les logs 🔍', 'error');
      }
    }
  }, 2000);
}

async function startCollect() {
  const arts = getSelectedArtifacts();
  if (!arts.length) { showToast('Sélectionnez au moins un artefact', 'warn'); return; }

  const btn = document.getElementById('btnCollect');
  btn.disabled = true;
  document.getElementById('buildProgress').classList.add('visible');
  document.getElementById('buildMsg').textContent = 'Lancement de la collecte...';

  const r = await fetch('/api/collector/build', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      artifacts: arts,
      target_os: document.getElementById('targetOS').value,
      velo_path: document.getElementById('veloPath2').value
    })
  });
  const d = await r.json();
  if (!d.ok) { showToast('Erreur : ' + d.error, 'error'); btn.disabled = false; return; }

  buildPollTimer = setInterval(pollBuildStatus, 2000);
}

async function pollBuildStatus() {
  const r = await fetch('/api/collector/status');
  const d = await r.json();
  if (d.lines && d.lines.length) {
    document.getElementById('buildMsg').textContent = d.lines[d.lines.length-1];
  }
  if (d.done) {
    clearInterval(buildPollTimer);
    document.getElementById('buildProgress').classList.remove('visible');
    document.getElementById('btnCollect').disabled = false;
    if (d.success) {
      showToast('Collecte terminée ! Résultat : ' + d.result, 'success');
      document.getElementById('snum1').textContent = '✓';
      goStep(2);
    } else {
      showToast('La collecte a échoué. Vérifiez les logs 🔍', 'error');
    }
  }
}

async function launchVeloGUI() {
  const r = await fetch('/api/velociraptor/gui', {method:'POST'});
  const d = await r.json();
  if (d.ok) { showToast('Velociraptor GUI lancé sur https://localhost:8889', 'success'); }
  else { showToast('Erreur : ' + d.error, 'error'); }
}

// ── ÉTAPE 2 : Import ─────────────────────────────────────────────────────────
function handleDrop(event) {
  event.preventDefault();
  document.getElementById('dropzone').classList.remove('drag');
  const f = event.dataTransfer.files[0];
  if (f) uploadCollection(f);
}

async function uploadCollection(file) {
  if (!file) return;
  document.getElementById('dropInfo').textContent = file.name + ' — ' + (file.size/1024/1024).toFixed(1) + ' Mo';
  document.getElementById('uploadProgress').classList.add('visible');

  const form = new FormData();
  form.append('collection', file);

  const r = await fetch('/api/collections/upload', {method:'POST', body:form});
  document.getElementById('uploadProgress').classList.remove('visible');

  if (!r.ok) {
    const d = await r.json().catch(() => ({error:'inconnue'}));
    showToast('Erreur import : ' + d.error, 'error');
    return;
  }
  const d = await r.json();
  showToast('Collection importée : ' + d.hostname + ' (' + d.artifacts + ' artefacts)', 'success');
  loadCollections();
}

async function loadCollections() {
  const r = await fetch('/api/collections');
  const cols = await r.json();
  const el = document.getElementById('colList');
  const btnAnalysis = document.getElementById('btnToAnalysis');

  if (!cols || !cols.length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:20px">Aucune collection importée</div>';
    btnAnalysis.disabled = true;
    return;
  }

  el.innerHTML = cols.map(function(c) {
    return '<div class="col-card ' + (selectedCollectionId===c.id?'selected':'') + '" onclick="selectCollection(\''+c.id+'\',\''+esc(c.hostname)+'\',\''+esc(c.os_name)+'\',\''+esc(c.artifacts)+'\')">' +
      '<div class="col-info">' +
        '<div class="col-hostname">' + esc(c.hostname) + '</div>' +
        '<div class="col-meta">' + esc(c.os_name) + ' \xb7 ' + c.imported_at.slice(0,16).replace('T',' ') + ' \xb7 ' + c.artifacts.split(',').filter(Boolean).length + ' artefacts</div>' +
      '</div>' +
      '<div><div class="col-status ' + c.status + '">' + c.status + '</div></div>' +
    '</div>';
  }).join('');

  if (selectedCollectionId) btnAnalysis.disabled = false;
}

function selectCollection(id, hostname, os, artifacts) {
  selectedCollectionId = id;
  selectedCollectionInfo = {id, hostname, os, artifacts};
  document.getElementById('btnToAnalysis').disabled = false;
  loadCollections();
  showToast('Collection sélectionnée : ' + hostname, 'info');
}

// ── ÉTAPE 3 : Analyse IA ─────────────────────────────────────────────────────
function refreshSelectedCol() {
  const el = document.getElementById('selectedColInfo');
  if (!selectedCollectionInfo) {
    el.innerHTML = '<div style="color:var(--muted);font-size:13px">Retournez à l\'étape 2 pour sélectionner une collection</div>';
    return;
  }
  const c = selectedCollectionInfo;
  el.innerHTML =
    '<div style="display:flex;align-items:center;gap:12px">' +
      '<span style="font-size:24px">\uD83D\uDDA5\uFE0F</span>' +
      '<div>' +
        '<div style="font-weight:700;color:var(--text);font-size:15px">' + esc(c.hostname) + '</div>' +
        '<div style="font-size:11px;color:var(--muted);font-family:var(--font-mono)">' + esc(c.os) + ' \xb7 ' + c.artifacts.split(',').filter(Boolean).length + ' artefacts collect\xe9s</div>' +
      '</div>' +
    '</div>';
}

async function startAnalysis() {
  if (!selectedCollectionId) { showToast('Sélectionnez une collection à l\'étape 2', 'warn'); return; }

  const btn = document.getElementById('btnStartAnalysis');
  btn.disabled = true;
  document.getElementById('analysisProgress').classList.add('visible');
  document.getElementById('analysisResult').style.display = 'none';
  document.getElementById('analysisMsg').textContent = 'Démarrage du moteur IA...';

  const r = await fetch('/api/analysis/start', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({collection_id: selectedCollectionId})
  });
  const d = await r.json();
  if (!d.ok) {
    showToast('Erreur : ' + d.error, 'error');
    btn.disabled = false;
    document.getElementById('analysisProgress').classList.remove('visible');
    return;
  }

  analysisPollTimer = setInterval(pollAnalysisStatus, 3000);
  animateAnalysisProgress();
}

let analysisFillPct = 10;
function animateAnalysisProgress() {
  if (analysisPollTimer === null) return;
  analysisFillPct = Math.min(90, analysisFillPct + Math.random() * 8);
  document.getElementById('analysisFill').style.width = analysisFillPct + '%';
  setTimeout(animateAnalysisProgress, 4000);
}

const analysisMsgs = [
  'Initialisation du moteur IA...',
  'Chargement du modèle (peut prendre 30-60s)...',
  'Construction du contexte forensique...',
  'Analyse des artefacts en cours...',
  'Identification des comportements suspects...',
  'Corrélation MITRE ATT&CK...',
  'Génération du rapport forensique...',
];
let analysisMsgIdx = 0;

async function pollAnalysisStatus() {
  analysisMsgIdx = (analysisMsgIdx + 1) % analysisMsgs.length;
  document.getElementById('analysisMsg').textContent = analysisMsgs[analysisMsgIdx];

  const r = await fetch('/api/analysis/status');
  const d = await r.json();

  if (d.done || !d.running) {
    clearInterval(analysisPollTimer);
    analysisPollTimer = null;
    document.getElementById('analysisProgress').classList.remove('visible');
    document.getElementById('btnStartAnalysis').disabled = false;
    document.getElementById('analysisFill').style.width = '100%';

    if (d.error) {
      showToast('Analyse échouée : ' + d.error, 'error');
      return;
    }
    if (d.has_result) {
      loadAnalysisResult();
    }
  }
}

async function loadAnalysisResult() {
  if (!selectedCollectionId) return;
  const r = await fetch('/api/analysis/result?id=' + selectedCollectionId);
  if (!r.ok) return;
  analysisData = await r.json();
  renderAnalysisResult(analysisData);
  document.getElementById('btnToReport').disabled = false;
  showToast('Analyse IA terminée — Niveau : ' + analysisData.threat_level, 'success');
  document.getElementById('snum3').textContent = '✓';
}

function renderAnalysisResult(d) {
  const el = document.getElementById('analysisResult');
  el.style.display = 'block';

  // Badge niveau
  const badge = document.getElementById('threatBadge');
  badge.textContent = d.threat_level || '—';
  badge.className = 'threat-badge threat-' + (d.threat_level || 'BENIN');

  document.getElementById('compromisedStatus').textContent =
    'État : ' + (d.compromised || '—');
  document.getElementById('engineName').textContent =
    'Moteur IA : ' + (d.engine || '—') + ' • ' + (d.generated_at||'').slice(0,16).replace('T',' ');

  document.getElementById('execSummary').textContent = d.executive_summary || '—';

  // Découvertes
  document.getElementById('keyFindings').innerHTML = (d.key_findings||[])
    .map(f => '<div class="finding-item">🔍 ' + esc(f) + '</div>').join('') || '<div style="color:var(--muted)">Aucune</div>';

  // Processus suspects
  document.getElementById('suspProcs').innerHTML = (d.suspicious_processes||[])
    .map(p => '<div class="finding-item">⚙️ ' + esc(p) + '</div>').join('') || '<div style="color:var(--muted)">Aucun</div>';

  // Réseau
  document.getElementById('suspNet').innerHTML = (d.suspicious_network||[])
    .map(n => '<div class="finding-item">🌐 ' + esc(n) + '</div>').join('') || '<div style="color:var(--muted)">Aucun</div>';

  // Persistance
  document.getElementById('persistMechs').innerHTML = (d.persistence_mechanisms||[])
    .map(p => '<div class="finding-item">🔒 ' + esc(p) + '</div>').join('') || '<div style="color:var(--muted)">Aucun</div>';

  // IOCs
  document.getElementById('iocList').innerHTML = (d.iocs||[])
    .map(i => '<div class="ioc-row"><span class="ioc-type">' + esc(i.type) + '</span><span style="font-family:var(--font-mono);font-size:12px;color:var(--text)">' + esc(i.value) + '</span><span style="font-size:11px;color:var(--muted);margin-left:8px">' + esc(i.desc) + '</span></div>').join('') || '<div style="color:var(--muted)">Aucun IOC identifié</div>';

  // MITRE
  document.getElementById('mitreList').innerHTML = (d.mitre_techniques||[])
    .map(m => '<span class="mitre-pill" title="' + esc(m.desc) + '">' + esc(m.id) + ' · ' + esc(m.name) + '</span>').join('') || '<div style="color:var(--muted)">Aucune technique identifiée</div>';

  // Timeline
  document.getElementById('timeline').innerHTML = (d.timeline||[])
    .map(t => '<div class="timeline-item"><span class="timeline-time">' + esc(t.time) + '</span><div><div class="timeline-evt">' + esc(t.event) + '</div><div class="timeline-src">' + esc(t.source) + '</div></div></div>').join('') || '<div style="color:var(--muted)">Aucune timeline</div>';

  // Recommandations
  document.getElementById('recommendations').innerHTML = (d.recommendations||[])
    .map((rec, i) => '<div class="finding-item"><strong style="color:var(--blue)">' + (i+1) + '.</strong> ' + esc(rec) + '</div>').join('') || '<div style="color:var(--muted)">Aucune recommandation</div>';
}

// ── ÉTAPE 4 : Rapport ────────────────────────────────────────────────────────
function refreshReportSummary() {
  const el = document.getElementById('reportSummary');
  if (!analysisData) {
    el.innerHTML = '<div style="color:var(--muted);font-size:13px">Retournez à l\'étape 3 pour lancer l\'analyse IA</div>';
    return;
  }
  const d = analysisData;
  el.innerHTML =
    '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">' +
      '<div class="threat-badge threat-' + (d.threat_level||'BENIN') + '" style="font-size:14px">' + esc(d.threat_level||'\u2014') + '</div>' +
      '<div>' +
        '<div style="font-weight:700;color:var(--text)">' + esc(d.hostname||'\u2014') + '</div>' +
        '<div style="font-size:12px;color:var(--muted)">' + esc(d.engine||'\u2014') + ' \xb7 ' + (d.iocs||[]).length + ' IOCs \xb7 ' + (d.mitre_techniques||[]).length + ' techniques MITRE</div>' +
      '</div>' +
    '</div>' +
    '<p style="margin-top:10px;font-size:13px;color:var(--text);line-height:1.6">' + esc((d.executive_summary||'').slice(0,200)) + '...</p>';
}

async function downloadReport() {
  if (!selectedCollectionId) { showToast('Aucune collection analysée', 'warn'); return; }
  const btn = document.getElementById('btnDownload');
  btn.disabled = true;
  showToast('Génération du rapport en cours...', 'info');
  try {
    const r = await fetch('/api/report/export?id=' + selectedCollectionId);
    if (!r.ok) { showToast('Erreur lors de la génération', 'error'); return; }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const cd   = r.headers.get('Content-Disposition');
    let fn     = 'rapport_forensique.docx';
    if (cd) { const m = cd.match(/filename="([^"]+)"/); if (m) fn = m[1]; }
    a.href = url; a.download = fn;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Rapport téléchargé : ' + fn, 'success');
    document.getElementById('snum4').textContent = '✓';
  } catch(e) { showToast('Erreur : ' + e.message, 'error'); }
  btn.disabled = false;
}

function startOver() {
  selectedCollectionId = null;
  selectedCollectionInfo = null;
  analysisData = null;
  for (let i=1;i<=4;i++) document.getElementById('snum'+i).textContent=i;
  goStep(1);
  showToast('Prêt pour une nouvelle analyse', 'info');
}

// ── Logs window ──────────────────────────────────────────────────────────────
let logOpen = false, logSSE = null, logCnt = 0;

function toggleLog() {
  const win = document.getElementById('logWindow');
  const btn = document.getElementById('logBtn');
  logOpen = !logOpen;
  win.classList.toggle('open', logOpen);
  btn.classList.toggle('active', logOpen);
  if (logOpen && !logSSE) startLogStream();
}

function colorizeLog(line) {
  if (line.includes('[COLLECTOR]') || line.includes('[VELO]')) return 'lcollector';
  if (line.includes('[IA]')) return 'lia';
  if (line.includes('[RAPPORT]')) return 'lrapport';
  if (line.includes('WARN') || line.includes('[!]') || line.includes('ERREUR')) return 'lwarn';
  if (line.includes('ERROR') || line.includes('[FAIL]')) return 'lerror';
  return 'linfo';
}

function appendLog(line) {
  if (!line.trim()) return;
  const el = document.getElementById('logContent');
  const div = document.createElement('div');
  div.className = 'log-line ' + colorizeLog(line);
  div.textContent = line;
  el.appendChild(div);
  if (el.scrollHeight - el.scrollTop - el.clientHeight < 60) el.scrollTop = el.scrollHeight;
  logCnt++;
  const c = document.getElementById('logCnt');
  if (c) c.textContent = '(' + logCnt + ')';
  while (el.childElementCount > 500) el.removeChild(el.firstChild);
}

function clearLogs() { document.getElementById('logContent').innerHTML = ''; logCnt = 0; }

function startLogStream() {
  logSSE = new EventSource('/api/logs/stream');
  logSSE.onmessage = e => { if (e.data && e.data !== ': keepalive') appendLog(e.data); };
}

// Drag
(function() {
  let dragging=false, ox=0, oy=0;
  document.addEventListener('mousedown', e => {
    const b = document.getElementById('logBar');
    if (!b || !b.contains(e.target)) return;
    const w = document.getElementById('logWindow');
    if (!w) return;
    dragging = true;
    const r = w.getBoundingClientRect();
    w.style.right='auto'; w.style.bottom='auto';
    w.style.left=r.left+'px'; w.style.top=r.top+'px';
    ox=e.clientX-r.left; oy=e.clientY-r.top;
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const w = document.getElementById('logWindow');
    if (!w) return;
    w.style.left=Math.max(0,Math.min(window.innerWidth-80,e.clientX-ox))+'px';
    w.style.top=Math.max(0,Math.min(window.innerHeight-40,e.clientY-oy))+'px';
  });
  document.addEventListener('mouseup', () => { dragging=false; });
})();

// Resize
(function() {
  let resizing=false, sx=0, sy=0, sw=0, sh=0;
  document.addEventListener('mousedown', e => {
    const h = document.getElementById('logResize');
    if (!h || !h.contains(e.target)) return;
    const w = document.getElementById('logWindow');
    resizing=true; sx=e.clientX; sy=e.clientY; sw=w.offsetWidth; sh=w.offsetHeight;
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!resizing) return;
    const w = document.getElementById('logWindow');
    w.style.width=Math.max(320,sw+(e.clientX-sx))+'px';
    w.style.height=Math.max(140,sh+(e.clientY-sy))+'px';
  });
  document.addEventListener('mouseup', () => { resizing=false; });
})();

// ── Utils ────────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showToast(msg, type='info') {
  let t = document.getElementById('_toast');
  if (!t) {
    t = document.createElement('div');
    t.id = '_toast';
    t.style.cssText='position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:11px 20px;border-radius:9px;font-size:13px;z-index:99999;max-width:420px;transition:opacity .3s;text-align:center';
    document.body.appendChild(t);
  }
  const colors={success:'#22c55e',error:'#ef4444',warn:'#f59e0b',info:'#00b4ff'};
  t.style.background='rgba(7,16,32,.97)';
  t.style.border='1px solid '+(colors[type]||'#00b4ff');
  t.style.color=colors[type]||'#c8daf0';
  t.style.opacity='1'; t.textContent=msg;
  clearTimeout(t._to);
  t._to=setTimeout(()=>{t.style.opacity='0';},3500);
}

// ── Init ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  detectVelo();
  loadArtifacts();
});
</script>
</body>
</html>
`
