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

// veloGUIURL stocke l'URL avec token capturée depuis velociraptor gui stdout.
var veloGUIURL string
var veloGUIURLMu sync.Mutex

func handleLaunchVeloGUI(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	cfg := *currentCfg
	cfgMu.RUnlock()

	bin := findVelociraptorBin(cfg.VeloRaptorBin)
	if bin == "" {
		http.Error(w, `{"error":"velociraptor.exe introuvable"}`, http.StatusNotFound)
		return
	}

	log.Printf("[VELO] Lancement GUI : %s", bin)

	// Réinitialiser l'URL
	veloGUIURLMu.Lock()
	veloGUIURL = ""
	veloGUIURLMu.Unlock()

	// velociraptor gui génère automatiquement une URL avec token dans sa sortie.
	// Format : "https://localhost:8889/app/index.html?username=...&password=..."
	// On capture stdout/stderr pour extraire cette URL et l'ouvrir directement
	// sans que l'utilisateur n'ait à saisir de mot de passe.
	cmd := exec.Command(bin, "gui")

	// Pipe stdout+stderr pour capturer l'URL
	go func() {
		out, err := cmd.CombinedOutput() // non bloquant : on lance en background
		_ = err
		// Parser la sortie pour trouver l'URL avec le token
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "localhost") && strings.Contains(line, "password=") {
				// Extraire l'URL
				for _, word := range strings.Fields(line) {
					if strings.HasPrefix(word, "http") && strings.Contains(word, "password=") {
						veloGUIURLMu.Lock()
						veloGUIURL = strings.TrimRight(word, "\"'")
						veloGUIURLMu.Unlock()
						log.Printf("[VELO] URL GUI capturée : %s", veloGUIURL)
						openBrowser(veloGUIURL)
						return
					}
				}
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	// Ouvrir le navigateur après délai — velociraptor gui prend ~2s à démarrer.
	// L'URL avec token sera capturée et rouvrira le bon lien automatiquement.
	go func() {
		// Attendre que velociraptor démarre et émette son URL
		for i := 0; i < 15; i++ {
			time.Sleep(1 * time.Second)
			veloGUIURLMu.Lock()
			url := veloGUIURL
			veloGUIURLMu.Unlock()
			if url != "" {
				return // déjà ouvert par la goroutine de capture
			}
		}
		// Fallback si on n'a pas capturé l'URL (version GUI sans token dans stdout)
		veloGUIURLMu.Lock()
		if veloGUIURL == "" {
			veloGUIURL = "https://localhost:8889"
			veloGUIURLMu.Unlock()
			log.Printf("[VELO] URL non capturée, ouverture directe (sans token)")
			openBrowser("https://localhost:8889")
		} else {
			veloGUIURLMu.Unlock()
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"msg":"Velociraptor GUI en cours de démarrage... L'interface s'ouvrira automatiquement."}`))
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
:root{
  --bg:#030a14;--bg2:#071020;--card:#0b1929;--card2:#0e1f34;
  --blue:#00b4ff;--cyan:#00e5ff;--green:#00ff9d;--yellow:#ffb830;
  --warn:#f59e0b;--red:#ff4466;--purple:#b04fff;
  --text:#c8daf0;--muted:#5a7a9a;--border:rgba(0,180,255,0.12);
  --font-ui:'Exo 2',sans-serif;--font-mono:'JetBrains Mono',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:14px;min-height:100vh}
header{background:linear-gradient(135deg,#040e1c,#071826);border-bottom:1px solid var(--border);
  padding:0 24px;height:58px;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:200;}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:38px;height:38px;background:linear-gradient(135deg,var(--blue),var(--cyan));
  border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:22px}
.logo-title{font-size:17px;font-weight:700}
.logo-sub{font-size:11px;color:var(--muted);font-family:var(--font-mono)}
.hdr-right{display:flex;align-items:center;gap:10px}
.badge{background:rgba(0,180,255,.1);border:1px solid rgba(0,180,255,.3);color:var(--blue);
  padding:4px 11px;border-radius:20px;font-size:11px;font-weight:600;font-family:var(--font-mono)}
.btn-log{background:transparent;border:1px solid var(--border);color:var(--muted);
  width:36px;height:36px;border-radius:8px;font-size:17px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:.2s}
.btn-log:hover,.btn-log.active{border-color:var(--blue);color:var(--blue);background:rgba(0,180,255,.08)}

/* Stepper */
.stepper{display:flex;align-items:center;justify-content:center;padding:18px 24px 0;max-width:1200px;margin:0 auto}
.step{display:flex;flex-direction:column;align-items:center;gap:6px;flex:1;cursor:pointer;
  padding:12px 8px;border-radius:10px;border:1px solid transparent;transition:.2s}
.step:hover{background:rgba(0,180,255,.04);border-color:var(--border)}
.step.active{background:rgba(0,180,255,.08);border-color:rgba(0,180,255,.3)}
.step.done .step-num{background:var(--green);color:#000}
.step-num{width:34px;height:34px;border-radius:50%;background:var(--card2);border:2px solid var(--border);
  display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:var(--muted)}
.step.active .step-num{background:var(--blue);color:#fff;border-color:var(--blue)}
.step-label{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;text-align:center}
.step.active .step-label{color:var(--blue)}
.step-icon{font-size:18px}
.step-conn{width:40px;height:2px;background:var(--border);flex-shrink:0}

/* Layout */
.main{max-width:1200px;margin:0 auto;padding:20px 24px 60px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:20px;display:none}
.panel.active{display:block}
.panel-hdr{background:linear-gradient(90deg,var(--card2),rgba(0,180,255,.04));border-bottom:1px solid var(--border);
  padding:14px 20px;display:flex;align-items:center;gap:12px}
.panel-hdr h2{font-size:14px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.8px}
.step-badge{background:var(--blue);color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px}
.panel-body{padding:20px}

/* Cards workflow */
.workflow-cards{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:20px}
.wf-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px}
.wf-card-title{font-size:12px;font-weight:700;color:var(--blue);text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.wf-card p{font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:10px}

/* Velo status */
.velo-panel{border-radius:9px;padding:14px 16px;margin-bottom:16px;border:1px solid var(--border)}
.velo-ok{background:rgba(0,255,157,.05);border-color:rgba(0,255,157,.25)}
.velo-warn{background:rgba(255,180,0,.04);border-color:rgba(255,180,0,.25)}
.velo-status-row{display:flex;align-items:center;gap:10px;margin-bottom:0}
.velo-icon{font-size:22px}
.velo-title{font-weight:700;font-size:14px}
.velo-path{font-size:11px;color:var(--muted);font-family:var(--font-mono);margin-top:2px}

/* Build panel */
.build-section{background:rgba(0,0,0,.2);border-radius:8px;padding:14px;border-left:3px solid var(--yellow);margin-top:12px}
.build-section-title{font-size:12px;font-weight:700;color:var(--yellow);margin-bottom:8px;display:flex;align-items:center;gap:8px}
.build-info{font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.6}
.build-output{font-family:var(--font-mono);font-size:10.5px;color:var(--muted);max-height:140px;
  overflow-y:auto;background:rgba(0,0,0,.3);border-radius:6px;padding:8px;display:none;margin-top:8px;white-space:pre-wrap}

/* Gauge de progression */
.gauge-wrap{display:none;flex-direction:column;gap:6px;margin:10px 0}
.gauge-wrap.visible{display:flex}
.gauge-track{height:8px;background:var(--bg2);border-radius:4px;overflow:hidden;border:1px solid var(--border)}
.gauge-fill{height:100%;border-radius:4px;transition:width .4s ease;width:0%}
.gauge-fill.compiling{background:linear-gradient(90deg,var(--yellow),#f97316);animation:gaugeShine 1.5s infinite}
.gauge-fill.done-ok{background:linear-gradient(90deg,var(--green),#00c870)}
.gauge-fill.done-err{background:linear-gradient(90deg,var(--red),#cc0033)}
@keyframes gaugeShine{0%,100%{opacity:1}50%{opacity:.7}}
.gauge-label{font-size:11px;color:var(--muted);font-family:var(--font-mono)}

/* Artefacts */
.art-groups{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;margin-bottom:20px}
.art-group{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:14px}
.art-group-hdr{display:flex;align-items:center;gap:8px;margin-bottom:10px;
  font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.6px;cursor:pointer}
.art-item{display:flex;align-items:center;gap:8px;padding:3px 0}
.art-item input{accent-color:var(--blue)}
.art-item label{font-family:var(--font-mono);font-size:11px;color:var(--muted);cursor:pointer}
.art-item label:hover{color:var(--text)}

/* Progress */
.progress-wrap{display:none;flex-direction:column;gap:7px;margin:12px 0}
.progress-wrap.visible{display:flex}
.progress-track{height:6px;background:var(--bg2);border-radius:3px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:3px;transition:width .3s;width:0%}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

/* Collection list */
.col-list{display:flex;flex-direction:column;gap:10px}
.col-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;
  padding:14px 16px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;transition:.2s}
.col-card:hover{border-color:rgba(0,180,255,.3)}
.col-card.selected{border-color:var(--blue);background:rgba(0,180,255,.06)}
.col-hostname{font-weight:700;color:var(--text);font-size:14px}
.col-meta{font-size:11px;color:var(--muted);margin-top:3px;font-family:var(--font-mono)}
.col-status{font-size:11px;padding:3px 9px;border-radius:12px;font-weight:600}
.col-status.imported{background:rgba(0,180,255,.1);color:var(--blue)}
.col-status.analysed{background:rgba(0,255,157,.1);color:var(--green)}

/* Dropzone */
.dropzone{border:2px dashed var(--border);border-radius:10px;padding:40px 20px;text-align:center;
  cursor:pointer;transition:.2s;margin-bottom:16px}
.dropzone:hover,.dropzone.drag{border-color:var(--blue);background:rgba(0,180,255,.04)}

/* Analysis result */
.report-section{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:16px;margin-bottom:14px}
.report-section h3{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px}
.threat-badge{display:inline-block;padding:6px 16px;border-radius:8px;font-weight:700;font-size:16px;letter-spacing:1px;margin-bottom:12px}
.threat-CRITIQUE{background:rgba(239,68,68,.15);color:#ef4444}
.threat-ELEVE{background:rgba(245,158,11,.15);color:#f59e0b}
.threat-MOYEN{background:rgba(234,179,8,.15);color:#eab308}
.threat-FAIBLE{background:rgba(34,197,94,.15);color:#22c55e}
.threat-BENIN{background:rgba(107,114,128,.15);color:#9ca3af}
.finding-item{padding:7px 10px;margin-bottom:5px;border-radius:6px;background:rgba(0,0,0,.2);border-left:3px solid var(--blue);font-size:12.5px;color:var(--text)}
.ioc-row{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(0,180,255,.06)}
.ioc-type{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;background:rgba(0,180,255,.1);color:var(--blue);font-family:var(--font-mono);flex-shrink:0}
.mitre-pill{display:inline-block;background:rgba(176,79,255,.15);color:#b04fff;border-radius:5px;padding:3px 8px;font-size:11px;font-family:var(--font-mono);margin:3px}
.timeline-item{display:flex;gap:12px;padding:7px 0;border-bottom:1px solid rgba(0,180,255,.06)}
.timeline-time{font-family:var(--font-mono);font-size:11px;color:var(--blue);flex-shrink:0;width:55px}

/* Forms */
.form-row{margin-bottom:14px}
label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:600;display:block;margin-bottom:5px}
input[type="text"],select{width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:7px;
  padding:9px 12px;color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none}
input:focus,select:focus{border-color:var(--blue)}

/* Buttons */
.btn{padding:9px 18px;border-radius:8px;border:none;cursor:pointer;font-family:var(--font-ui);font-weight:600;font-size:13px;transition:.2s}
.btn-primary{background:linear-gradient(135deg,var(--blue),#0090d4);color:#fff}
.btn-primary:hover{opacity:.88}
.btn-primary:disabled{opacity:.45;cursor:not-allowed}
.btn-success{background:linear-gradient(135deg,var(--green),#00c870);color:#000}
.btn-success:hover{opacity:.88}
.btn-success:disabled{opacity:.45;cursor:not-allowed}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--muted)}
.btn-ghost:hover{border-color:var(--blue);color:var(--blue)}
.btn-purple{background:linear-gradient(135deg,#7c3aed,#5b21b6);color:#fff}
.btn-purple:hover{opacity:.88}
.btn-purple:disabled{opacity:.45;cursor:not-allowed}
.btn-yellow{background:linear-gradient(135deg,var(--yellow),#f97316);color:#000}
.btn-yellow:hover{opacity:.88}
.btn-yellow:disabled{opacity:.45;cursor:not-allowed}
.btn-row{display:flex;gap:10px;flex-wrap:wrap}

/* Log window */
#logWindow{position:fixed;bottom:24px;right:24px;width:700px;height:340px;
  background:rgba(3,10,20,.97);border:1px solid rgba(0,180,255,.28);border-radius:12px;
  box-shadow:0 8px 40px rgba(0,0,0,.75);display:none;flex-direction:column;
  z-index:9999;overflow:hidden;min-width:320px;min-height:140px;backdrop-filter:blur(10px)}
#logWindow.open{display:flex}
.log-titlebar{background:linear-gradient(90deg,#040e1c,rgba(0,180,255,.06));
  border-bottom:1px solid rgba(0,180,255,.15);padding:8px 14px;
  display:flex;align-items:center;justify-content:space-between;cursor:grab;user-select:none;flex-shrink:0}
.log-titlebar:active{cursor:grabbing}
.log-title{font-size:11px;font-weight:700;color:var(--blue);letter-spacing:1px;text-transform:uppercase;display:flex;align-items:center;gap:8px}
.log-dot{width:7px;height:7px;border-radius:50%;background:var(--blue);animation:lpulse 1.8s infinite}
@keyframes lpulse{0%,100%{opacity:1}50%{opacity:.3}}
.log-close{cursor:pointer;color:var(--muted);font-size:15px;padding:2px 5px;border-radius:4px}
.log-close:hover{color:var(--red);background:rgba(255,68,102,.12)}
#logContent{flex:1;overflow-y:auto;padding:9px 13px;font-family:var(--font-mono);font-size:11.5px;line-height:1.65}
.log-line{white-space:pre-wrap;word-break:break-all;padding:1px 0}
.log-line.lbuild{color:#ffb830}.log-line.lcol{color:#00b4ff}.log-line.lia{color:#00ff9d}
.log-line.lwarn{color:#f59e0b}.log-line.lerr{color:#ff4466}.log-line.linfo{color:#8da9c4}
.log-resize{position:absolute;bottom:0;right:0;width:18px;height:18px;cursor:se-resize;
  background:linear-gradient(135deg,transparent 50%,rgba(0,180,255,.4) 50%);border-radius:0 0 12px 0}

::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
@media(max-width:900px){.workflow-cards{grid-template-columns:1fr}.art-groups{grid-template-columns:1fr}}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">&#x1F996;</div>
    <div>
      <div class="logo-title">Velociraptor-IA</div>
      <div class="logo-sub">Forensique DFIR &bull; Analyse IA locale</div>
    </div>
  </div>
  <div class="hdr-right">
    <div class="badge">DFIR PLATFORM</div>
    <button class="btn-log" id="logBtn" onclick="toggleLog()" title="Logs temps r&#233;el">&#x1F50D;</button>
  </div>
</header>

<!-- Fenetre logs -->
<div id="logWindow">
  <div class="log-titlebar" id="logBar">
    <div class="log-title"><div class="log-dot"></div><span>Logs serveur</span><span id="logCnt" style="font-size:10px;color:var(--muted)"></span></div>
    <div style="display:flex;gap:8px;align-items:center">
      <span style="font-size:10px;color:var(--muted);cursor:pointer" onclick="clearLogs()">&#x1F5D1;</span>
      <span class="log-close" onclick="toggleLog()">&#x2715;</span>
    </div>
  </div>
  <div id="logContent"></div>
  <div class="log-resize" id="logResize"></div>
</div>

<!-- Stepper -->
<div class="stepper">
  <div class="step active" id="step-tab-1" onclick="goStep(1)"><div class="step-icon">&#x1F528;</div><div class="step-num" id="snum1">1</div><div class="step-label">Pr&#233;paration</div></div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-2" onclick="goStep(2)"><div class="step-icon">&#x1F4E6;</div><div class="step-num" id="snum2">2</div><div class="step-label">Collecte</div></div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-3" onclick="goStep(3)"><div class="step-icon">&#x1F4C2;</div><div class="step-num" id="snum3">3</div><div class="step-label">Import</div></div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-4" onclick="goStep(4)"><div class="step-icon">&#x1F9E0;</div><div class="step-num" id="snum4">4</div><div class="step-label">Analyse IA</div></div>
  <div class="step-conn"></div>
  <div class="step" id="step-tab-5" onclick="goStep(5)"><div class="step-icon">&#x1F4C4;</div><div class="step-num" id="snum5">5</div><div class="step-label">Rapport</div></div>
</div>

<div class="main">

<!-- ===== ETAPE 1 : PREPARATION ===== -->
<div class="panel active" id="panel1">
  <div class="panel-hdr"><span>&#x1F528;</span><h2>&#201;tape 1 &#8212; Pr&#233;paration : Compiler Velociraptor</h2><span class="step-badge">1/5</span></div>
  <div class="panel-body">

    <div class="workflow-cards">
      <div class="wf-card">
        <div class="wf-card-title"><span>1&#65039;&#8419;</span> Compiler velociraptor.exe</div>
        <p>Le projet <code style="color:var(--blue)">velociraptor-ia</code> est un fork du code source Velociraptor. La commande <code style="color:var(--green)">go run make.go -v windowsDev</code> produit <code style="color:var(--cyan)">output/velociraptor.exe</code>.</p>
        <p style="color:var(--warn);font-size:11px">Pr&#233;requis : Go &#x2265;1.23 &bull; GCC (TDM-GCC) &bull; Node.js</p>
      </div>
      <div class="wf-card">
        <div class="wf-card-title"><span>2&#65039;&#8419;</span> G&#233;n&#233;rer le Collector</div>
        <p>Ouvrir Velociraptor GUI &#8594; <strong>Server Artifacts &#8594; Build Collector</strong>. S&#233;lectionner les artefacts, choisir l&#8217;OS cible, t&#233;l&#233;charger le <code>Collector_windows.exe</code>.</p>
      </div>
      <div class="wf-card">
        <div class="wf-card-title"><span>3&#65039;&#8419;</span> D&#233;ployer &amp; Collecter</div>
        <p>D&#233;poser <code>Collector_windows.exe</code> sur la machine &#224; investiguer. L&#8217;ex&#233;cuter en Admin. Il produit un <code>Collection_*.zip</code> &#224; r&#233;cup&#233;rer pour l&#8217;&#233;tape 3.</p>
      </div>
    </div>

    <!-- Statut velociraptor.exe -->
    <div class="velo-panel" id="veloPanelMain">
      <div class="velo-status-row">
        <span class="velo-icon" id="veloIconMain">&#x23F3;</span>
        <div>
          <div class="velo-title" id="veloTitleMain">D&#233;tection de velociraptor.exe...</div>
          <div class="velo-path" id="veloPathMain"></div>
        </div>
        <button class="btn btn-ghost" style="margin-left:auto;padding:5px 12px;font-size:11px" onclick="detectVelo()">&#x1F504; D&#233;tecter</button>
      </div>

      <!-- Section compilation -->
      <div class="build-section" id="veloBuildSection" style="display:none">
        <div class="build-section-title">&#x1F528; Compiler velociraptor.exe depuis les sources</div>
        <div class="build-info" id="veloBuildInfo">Pr&#233;t &#224; compiler depuis le r&#233;pertoire du projet.</div>
        <div class="gauge-wrap" id="veloGauge">
          <div style="display:flex;align-items:center;gap:8px"><div class="spinner"></div><span id="veloGaugeLabel" class="gauge-label">Initialisation...</span></div>
          <div class="gauge-track"><div class="gauge-fill compiling" id="veloGaugeFill" style="width:5%"></div></div>
          <div id="veloGaugePct" style="font-size:10px;color:var(--muted);font-family:var(--font-mono)">0%</div>
        </div>
        <div class="btn-row" style="margin-top:8px">
          <button class="btn btn-yellow" id="btnCompileVelo" onclick="compileVelociraptor()">&#x1F528; Compiler velociraptor.exe</button>
        </div>
        <div class="build-output" id="veloBuildOutput"></div>
      </div>

      <!-- Bouton recompiler (visible quand trouve) -->
      <div id="veloRecompileRow" style="display:none;margin-top:12px">
        <div class="btn-row">
          <button class="btn btn-primary" onclick="launchVeloGUI()">&#x1F996; Ouvrir Velociraptor GUI</button>
          <button class="btn btn-yellow" id="btnRecompileVelo" onclick="compileVelociraptor()">&#x1F527; Recompiler velociraptor.exe</button>
        </div>
        <div class="gauge-wrap" id="veloRecompileGauge">
          <div style="display:flex;align-items:center;gap:8px"><div class="spinner"></div><span id="veloRecompileLabel" class="gauge-label">Compilation en cours...</span></div>
          <div class="gauge-track"><div class="gauge-fill compiling" id="veloRecompileFill" style="width:5%"></div></div>
        </div>
        <div class="build-output" id="veloRecompileOutput"></div>
      </div>
    </div>

    <div class="btn-row" style="margin-top:16px">
      <button class="btn btn-ghost" onclick="goStep(2)">Passer &#224; l&#8217;&#233;tape 2 &#8594;</button>
    </div>
  </div>
</div>

<!-- ===== ETAPE 2 : COLLECTE ===== -->
<div class="panel" id="panel2">
  <div class="panel-hdr"><span>&#x1F4E6;</span><h2>&#201;tape 2 &#8212; G&#233;n&#233;rer le Collector Velociraptor</h2><span class="step-badge">2/5</span></div>
  <div class="panel-body">

    <div style="background:rgba(0,180,255,.06);border:1px solid rgba(0,180,255,.2);border-radius:9px;padding:16px;margin-bottom:16px">
      <div style="font-weight:700;color:var(--blue);margin-bottom:10px">&#x1F4CB; Workflow de collecte Velociraptor</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;font-size:12px">
        <div style="background:rgba(0,0,0,.2);border-radius:7px;padding:12px">
          <div style="font-weight:700;color:var(--green);margin-bottom:6px">&#9312; Build Collector</div>
          <p style="color:var(--muted)">Dans Velociraptor GUI :<br>Server Artifacts &#8594; Build Collector<br>S&#233;lectionner les artefacts<br>T&#233;l&#233;charger <code>Collector.exe</code></p>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:7px;padding:12px">
          <div style="font-weight:700;color:var(--yellow);margin-bottom:6px">&#9313; Ex&#233;cuter sur la cible</div>
          <p style="color:var(--muted)">D&#233;poser <code>Collector.exe</code> sur la machine &#224; investiguer<br>Ex&#233;cuter en tant qu&#8217;Administrateur<br>R&#233;cup&#233;rer le <code>Collection_*.zip</code></p>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:7px;padding:12px">
          <div style="font-weight:700;color:var(--blue);margin-bottom:6px">&#9314; Importer l&#8217;archive</div>
          <p style="color:var(--muted)">Revenir sur cette IHM<br>&#201;tape 3 : glisser-d&#233;poser le ZIP<br>pour analyse forensique IA</p>
        </div>
      </div>
    </div>

    <!-- Selection artefacts + lancement collecte locale -->
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <label style="margin:0;font-size:12px;color:var(--text)">Artefacts &#224; inclure dans le Collector</label>
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="selectAll(true)">Tout</button>
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="selectAll(false)">Aucun</button>
        </div>
      </div>
      <div class="art-groups" id="artGroups"><div style="color:var(--muted)">Chargement...</div></div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
      <div class="form-row"><label>Chemin velociraptor.exe (optionnel)</label><input type="text" id="veloPath2" placeholder="Auto-d&#233;tect&#233; dans output/"></div>
      <div class="form-row"><label>OS cible du collector</label>
        <select id="targetOS"><option value="windows" selected>Windows (amd64)</option><option value="linux">Linux (amd64)</option><option value="darwin">macOS</option></select>
      </div>
    </div>

    <div class="progress-wrap" id="collectProgress">
      <div style="display:flex;align-items:center;gap:8px"><div class="spinner"></div><span id="collectMsg" style="font-size:13px;color:var(--muted)">Collecte en cours...</span></div>
      <div class="progress-track"><div class="progress-fill" id="collectFill"></div></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-ghost" onclick="goStep(1)">&#8592; Retour</button>
      <button class="btn btn-success" id="btnCollect" onclick="startCollect()" disabled>&#9654; Lancer la collecte locale</button>
      <button class="btn btn-primary" onclick="launchVeloGUI()">&#x1F996; Ouvrir Velociraptor GUI (Build Collector)</button>
      <button class="btn btn-ghost" onclick="goStep(3)">Passer &#224; l&#8217;import &#8594;</button>
    </div>
  </div>
</div>

<!-- ===== ETAPE 3 : IMPORT ===== -->
<div class="panel" id="panel3">
  <div class="panel-hdr"><span>&#x1F4C2;</span><h2>&#201;tape 3 &#8212; Importer la collecte</h2><span class="step-badge">3/5</span></div>
  <div class="panel-body">

    <div class="dropzone" id="dropzone"
      ondragover="event.preventDefault();this.classList.add('drag')"
      ondragleave="this.classList.remove('drag')"
      ondrop="handleDrop(event)"
      onclick="document.getElementById('fileInput').click()">
      <div style="font-size:36px;margin-bottom:10px">&#x1F4E6;</div>
      <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:6px">Glissez le ZIP de collecte Velociraptor ici</div>
      <div style="font-size:12px;color:var(--muted)">Fichier produit par le Collector sur la machine investigu&#233;e</div>
      <div id="dropInfo" style="margin-top:10px;font-size:12px;color:var(--blue)"></div>
    </div>
    <input type="file" id="fileInput" style="display:none" accept=".zip" onchange="uploadCol(this.files[0])">

    <div class="progress-wrap" id="uploadProgress">
      <div style="display:flex;align-items:center;gap:8px"><div class="spinner"></div><span style="font-size:13px;color:var(--muted)">Import en cours...</span></div>
    </div>

    <div id="colList" class="col-list" style="margin-top:16px">
      <div style="color:var(--muted);font-size:13px;text-align:center;padding:20px">Aucune collection import&#233;e</div>
    </div>

    <div class="btn-row" style="margin-top:16px">
      <button class="btn btn-ghost" onclick="goStep(2)">&#8592; Retour</button>
      <button class="btn btn-primary" id="btnToAnalysis" disabled onclick="goStep(4)">Analyser avec l&#8217;IA &#8594;</button>
    </div>
  </div>
</div>

<!-- ===== ETAPE 4 : ANALYSE IA ===== -->
<div class="panel" id="panel4">
  <div class="panel-hdr"><span>&#x1F9E0;</span><h2>&#201;tape 4 &#8212; Analyse forensique IA</h2><span class="step-badge">4/5</span></div>
  <div class="panel-body">

    <div id="selColInfo" style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:14px">
      <div style="color:var(--muted);font-size:13px">Aucune collection s&#233;lectionn&#233;e</div>
    </div>

    <div style="background:rgba(0,255,157,.06);border:1px solid rgba(0,255,157,.2);border-radius:8px;padding:12px 16px;margin-bottom:14px;font-size:12px">
      <strong style="color:var(--green)">&#x1F916; Moteur IA local</strong> &#8212; Mistral 7B (priorit&#233;) ou Qwen2.5 14B<br>
      <span style="color:var(--muted);font-size:11px">Chemin : <code>../moteur/llama-server.exe</code> + <code>../moteur/models/*.gguf</code></span>
    </div>

    <div class="progress-wrap" id="analysisProgress">
      <div style="display:flex;align-items:center;gap:8px"><div class="spinner"></div><span id="analysisMsg" style="font-size:13px;color:var(--muted)">Initialisation...</span></div>
      <div class="progress-track"><div class="progress-fill" id="analysisFill" style="width:10%"></div></div>
    </div>

    <div id="analysisResult" style="display:none">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <div id="threatBadge" class="threat-badge">&#8212;</div>
        <div>
          <div style="font-size:13px;font-weight:600" id="compromisedStatus">&#8212;</div>
          <div style="font-size:11px;color:var(--muted)" id="engineName">&#8212;</div>
        </div>
      </div>
      <div class="report-section"><h3>R&#233;sum&#233; ex&#233;cutif</h3><p id="execSummary" style="font-size:13px;line-height:1.7"></p></div>
      <div class="report-section"><h3>D&#233;couvertes cl&#233;s</h3><div id="keyFindings"></div></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="report-section"><h3>Processus suspects</h3><div id="suspProcs"></div></div>
        <div class="report-section"><h3>Trafic r&#233;seau suspect</h3><div id="suspNet"></div></div>
      </div>
      <div class="report-section"><h3>Persistance</h3><div id="persist"></div></div>
      <div class="report-section"><h3>IOCs</h3><div id="iocList"></div></div>
      <div class="report-section"><h3>MITRE ATT&amp;CK</h3><div id="mitreList"></div></div>
      <div class="report-section"><h3>Timeline</h3><div id="timeline"></div></div>
      <div class="report-section"><h3>Recommandations SOC</h3><div id="recos"></div></div>
    </div>

    <div class="btn-row" style="margin-top:14px">
      <button class="btn btn-ghost" onclick="goStep(3)">&#8592; Retour</button>
      <button class="btn btn-primary" id="btnStartAI" onclick="startAnalysis()">&#x1F9E0; Lancer l&#8217;analyse IA</button>
      <button class="btn btn-ghost" id="btnToReport" disabled onclick="goStep(5)">G&#233;n&#233;rer le rapport &#8594;</button>
    </div>
  </div>
</div>

<!-- ===== ETAPE 5 : RAPPORT ===== -->
<div class="panel" id="panel5">
  <div class="panel-hdr"><span>&#x1F4C4;</span><h2>&#201;tape 5 &#8212; Rapport DFIR</h2><span class="step-badge">5/5</span></div>
  <div class="panel-body">
    <div id="reportSummary" style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px">
      <div style="color:var(--muted);font-size:13px">Aucune analyse disponible</div>
    </div>
    <div class="btn-row">
      <button class="btn btn-ghost" onclick="goStep(4)">&#8592; Retour</button>
      <button class="btn btn-purple" id="btnDl" onclick="downloadReport()">&#x2B07; T&#233;l&#233;charger le rapport DFIR</button>
      <button class="btn btn-ghost" onclick="startOver()">&#x1F504; Nouvelle analyse</button>
    </div>
  </div>
</div>

</div><!-- .main -->

<script>
'use strict';
let curStep=1, selColId=null, selColInfo=null, aiData=null;
let buildPoll=null, analysisPoll=null, veloBuildPoll=null;

// ── Stepper ──────────────────────────────────────────────────────────────────
function goStep(n) {
  curStep=n;
  for(let i=1;i<=5;i++){
    document.getElementById('step-tab-'+i).classList.toggle('active',i===n);
    document.getElementById('panel'+i).classList.toggle('active',i===n);
    document.getElementById('step-tab-'+i).classList.toggle('done',i<n);
  }
  if(n===3) loadCols();
  if(n===4) refreshSelCol();
  if(n===5) refreshReportSummary();
}

// ── Etape 1 : Preparation ────────────────────────────────────────────────────
async function detectVelo() {
  const r = await fetch('/api/velociraptor/detect');
  const d = await r.json();
  const panel = document.getElementById('veloPanelMain');
  const icon  = document.getElementById('veloIconMain');
  const title = document.getElementById('veloTitleMain');
  const path  = document.getElementById('veloPathMain');
  const buildSec  = document.getElementById('veloBuildSection');
  const recompRow = document.getElementById('veloRecompileRow');
  const btnCollect = document.getElementById('btnCollect');
  if(d.found){
    panel.className='velo-panel velo-ok';
    icon.textContent='\u2705';
    title.textContent='Velociraptor pr\xeat';
    title.style.color='var(--green)';
    path.textContent=d.path;
    buildSec.style.display='none';
    recompRow.style.display='block';
    if(btnCollect) btnCollect.disabled=false;
  } else {
    panel.className='velo-panel velo-warn';
    icon.textContent='\u26a0\ufe0f';
    title.textContent='velociraptor.exe introuvable \u2014 compilation requise';
    title.style.color='var(--yellow)';
    path.textContent=d.make_go_exists?'make.go d\xe9tect\xe9 \u2014 compilation possible':'Racine projet non trouv\xe9e';
    buildSec.style.display='block';
    recompRow.style.display='none';
  }
}

async function compileVelociraptor() {
  // Determine which UI elements to use
  const isRecompile = document.getElementById('veloRecompileRow').style.display !== 'none';
  const btnId     = isRecompile ? 'btnRecompileVelo' : 'btnCompileVelo';
  const gaugeId   = isRecompile ? 'veloRecompileGauge' : 'veloGauge';
  const fillId    = isRecompile ? 'veloRecompileFill' : 'veloGaugeFill';
  const labelId   = isRecompile ? 'veloRecompileLabel' : 'veloGaugeLabel';
  const outId     = isRecompile ? 'veloRecompileOutput' : 'veloBuildOutput';

  const btn   = document.getElementById(btnId);
  const gauge = document.getElementById(gaugeId);
  const fill  = document.getElementById(fillId);
  const lbl   = document.getElementById(labelId);
  const out   = document.getElementById(outId);

  btn.disabled = true;
  gauge.classList.add('visible');
  out.style.display='block'; out.textContent='';
  fill.className='gauge-fill compiling'; fill.style.width='5%';

  const r = await fetch('/api/velociraptor/build', {method:'POST'});
  const d = await r.json();
  if(!d.ok){ showToast('Erreur : '+d.error,'error'); btn.disabled=false; return; }

  let pct=5;
  veloBuildPoll = setInterval(async()=>{
    const sr = await fetch('/api/velociraptor/build/status');
    const sd = await sr.json();
    if(sd.lines && sd.lines.length){
      out.textContent = sd.lines.join('\n');
      out.scrollTop = out.scrollHeight;
      const last = sd.lines.slice().reverse().find(l=>l.includes('[BUILD-VELO]')||l.includes('\u2713')||l.includes('ERREUR'));
      if(last) lbl.textContent = last.slice(0,80);
      // Avancer la gauge progressivement
      pct = Math.min(90, pct + (Math.random()*4));
      fill.style.width = pct+'%';
      if(document.getElementById('veloGaugePct')) document.getElementById('veloGaugePct').textContent=Math.round(pct)+'%';
    }
    if(sd.done){
      clearInterval(veloBuildPoll); veloBuildPoll=null;
      btn.disabled=false;
      fill.style.width='100%';
      if(sd.success){
        fill.className='gauge-fill done-ok';
        lbl.textContent='\u2713 Compil\xe9 avec succ\xe8s';
        showToast('\u2705 velociraptor.exe compil\xe9 !','success');
        await detectVelo();
        // Retry 3 fois si pas detect\xe9
        for(let i=0;i<3;i++){
          await new Promise(r=>setTimeout(r,1500));
          const dr=await fetch('/api/velociraptor/detect');
          const dd=await dr.json();
          if(dd.found){ await detectVelo(); break; }
        }
      } else {
        fill.className='gauge-fill done-err';
        lbl.textContent='Compilation \xe9chou\xe9e';
        showToast('Compilation \xe9chou\xe9e \u2014 v\xe9rifiez les logs \uD83D\uDD0D','error');
      }
    }
  }, 2000);
}

async function launchVeloGUI() {
  const r = await fetch('/api/velociraptor/gui',{method:'POST'});
  const d = await r.json();
  if(d.ok) showToast('Velociraptor GUI en cours de d\xe9marrage... L\'interface s\'ouvrira automatiquement','success');
  else showToast('Erreur : '+(d.error||'inconnue'),'error');
}

// ── Etape 2 : Collecte ───────────────────────────────────────────────────────
async function loadArtifacts(){
  const r=await fetch('/api/artifacts');
  const groups=await r.json();
  const c=document.getElementById('artGroups');
  c.innerHTML='';
  for(const grp of groups){
    const div=document.createElement('div');
    div.className='art-group';
    let html='<div class="art-group-hdr"><input type="checkbox" id="grp_'+grp.name+'" onchange="toggleGrp(\''+grp.name+'\',this.checked)"><span>'+grp.icon+'</span><label for="grp_'+grp.name+'" style="cursor:pointer">'+grp.label+'</label></div>';
    for(const a of grp.artifacts){
      const id='art_'+a.replace(/\./g,'_');
      html+='<div class="art-item"><input type="checkbox" id="'+id+'" value="'+a+'" class="art-cb" data-group="'+grp.name+'"><label for="'+id+'">'+a+'</label></div>';
    }
    div.innerHTML=html; c.appendChild(div);
  }
}

function toggleGrp(n,v){ document.querySelectorAll('[data-group="'+n+'"]').forEach(cb=>cb.checked=v); }
function selectAll(v){ document.querySelectorAll('.art-cb').forEach(cb=>cb.checked=v); document.querySelectorAll('[id^="grp_"]').forEach(cb=>cb.checked=v); }
function getSelectedArts(){ return Array.from(document.querySelectorAll('.art-cb:checked')).map(cb=>cb.value); }

async function startCollect(){
  const arts=getSelectedArts();
  if(!arts.length){ showToast('S\xe9lectionnez au moins un artefact','warn'); return; }
  const btn=document.getElementById('btnCollect');
  btn.disabled=true;
  document.getElementById('collectProgress').classList.add('visible');
  const r=await fetch('/api/collector/build',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({artifacts:arts,target_os:document.getElementById('targetOS').value,velo_path:document.getElementById('veloPath2').value})});
  const d=await r.json();
  if(!d.ok){ showToast('Erreur : '+d.error,'error'); btn.disabled=false; return; }
  buildPoll=setInterval(pollBuild,2000);
}

async function pollBuild(){
  const r=await fetch('/api/collector/status');
  const d=await r.json();
  if(d.lines&&d.lines.length) document.getElementById('collectMsg').textContent=d.lines[d.lines.length-1].slice(0,80);
  if(d.done){
    clearInterval(buildPoll); buildPoll=null;
    document.getElementById('collectProgress').classList.remove('visible');
    document.getElementById('btnCollect').disabled=false;
    if(d.success){ showToast('Collection termin\xe9e ! R\xe9cup\xe9rez le ZIP g\xe9n\xe9r\xe9.','success'); document.getElementById('snum2').textContent='\u2713'; }
    else showToast('Collecte \xe9chou\xe9e \u2014 utilisez Velociraptor GUI pour la collecte','error');
  }
}

// ── Etape 3 : Import ─────────────────────────────────────────────────────────
function handleDrop(e){
  e.preventDefault(); document.getElementById('dropzone').classList.remove('drag');
  const f=e.dataTransfer.files[0]; if(f) uploadCol(f);
}

async function uploadCol(file){
  if(!file) return;
  document.getElementById('dropInfo').textContent=file.name+' \u2014 '+(file.size/1024/1024).toFixed(1)+' Mo';
  document.getElementById('uploadProgress').classList.add('visible');
  const form=new FormData(); form.append('collection',file);
  const r=await fetch('/api/collections/upload',{method:'POST',body:form});
  document.getElementById('uploadProgress').classList.remove('visible');
  if(!r.ok){ const d=await r.json().catch(()=>({error:'inconnue'})); showToast('Erreur : '+d.error,'error'); return; }
  const d=await r.json();
  showToast('Import\xe9 : '+d.hostname+' ('+d.artifacts+' artefacts)','success');
  loadCols();
}

async function loadCols(){
  const r=await fetch('/api/collections');
  const cols=await r.json();
  const el=document.getElementById('colList');
  const btn=document.getElementById('btnToAnalysis');
  if(!cols||!cols.length){ el.innerHTML='<div style="color:var(--muted);font-size:13px;text-align:center;padding:20px">Aucune collection import\xe9e</div>'; btn.disabled=true; return; }
  el.innerHTML=cols.map(function(c){
    return '<div class="col-card '+(selColId===c.id?'selected':'')+'" onclick="selCol(\''+c.id+'\',\''+esc(c.hostname)+'\',\''+esc(c.os_name)+'\',\''+esc(c.artifacts)+'\')">' +
      '<div class="col-info"><div class="col-hostname">'+esc(c.hostname)+'</div><div class="col-meta">'+esc(c.os_name)+' \xb7 '+c.imported_at.slice(0,16).replace('T',' ')+' \xb7 '+c.artifacts.split(',').filter(Boolean).length+' artefacts</div></div>' +
      '<div><div class="col-status '+c.status+'">'+c.status+'</div></div></div>';
  }).join('');
  if(selColId) btn.disabled=false;
}

function selCol(id,hostname,os,artifacts){
  selColId=id; selColInfo={id,hostname,os,artifacts};
  document.getElementById('btnToAnalysis').disabled=false;
  loadCols(); showToast('S\xe9lectionn\xe9 : '+hostname,'info');
}

// ── Etape 4 : Analyse IA ─────────────────────────────────────────────────────
function refreshSelCol(){
  const el=document.getElementById('selColInfo');
  if(!selColInfo){ el.innerHTML='<div style="color:var(--muted);font-size:13px">Revenez \xe0 l\u2019\xe9tape 3 pour s\xe9lectionner une collection</div>'; return; }
  const c=selColInfo;
  el.innerHTML='<div style="display:flex;align-items:center;gap:12px"><span style="font-size:24px">\uD83D\uDDA5\uFE0F</span><div><div style="font-weight:700;font-size:15px">'+esc(c.hostname)+'</div><div style="font-size:11px;color:var(--muted);font-family:var(--font-mono)">'+esc(c.os)+' \xb7 '+c.artifacts.split(',').filter(Boolean).length+' artefacts collect\xe9s</div></div></div>';
}

let aiFillPct=10;
const aiMsgs=['Initialisation du moteur IA...','Chargement du mod\xe8le (30-60s)...','Analyse des artefacts VQL...','Identification des comportements suspects...','Corr\xe9lation MITRE ATT&CK...','G\xe9n\xe9ration du rapport forensique...'];
let aiMsgIdx=0;

async function startAnalysis(){
  if(!selColId){ showToast('S\xe9lectionnez une collection \xe0 l\u2019\xe9tape 3','warn'); return; }
  const btn=document.getElementById('btnStartAI');
  btn.disabled=true;
  document.getElementById('analysisProgress').classList.add('visible');
  document.getElementById('analysisResult').style.display='none';
  aiFillPct=10;
  const r=await fetch('/api/analysis/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({collection_id:selColId})});
  const d=await r.json();
  if(!d.ok){ showToast('Erreur : '+d.error,'error'); btn.disabled=false; document.getElementById('analysisProgress').classList.remove('visible'); return; }
  analysisPoll=setInterval(pollAnalysis,3000);
  animAI();
}

function animAI(){
  if(!analysisPoll) return;
  aiMsgIdx=(aiMsgIdx+1)%aiMsgs.length;
  document.getElementById('analysisMsg').textContent=aiMsgs[aiMsgIdx];
  aiFillPct=Math.min(90,aiFillPct+Math.random()*7);
  document.getElementById('analysisFill').style.width=aiFillPct+'%';
  setTimeout(animAI,4000);
}

async function pollAnalysis(){
  const r=await fetch('/api/analysis/status');
  const d=await r.json();
  if(d.done||!d.running){
    clearInterval(analysisPoll); analysisPoll=null;
    document.getElementById('analysisProgress').classList.remove('visible');
    document.getElementById('analysisFill').style.width='100%';
    document.getElementById('btnStartAI').disabled=false;
    if(d.error){ showToast('Analyse \xe9chou\xe9e : '+d.error,'error'); return; }
    if(d.has_result) loadAIResult();
  }
}

async function loadAIResult(){
  if(!selColId) return;
  const r=await fetch('/api/analysis/result?id='+selColId);
  if(!r.ok) return;
  aiData=await r.json();
  renderAI(aiData);
  document.getElementById('btnToReport').disabled=false;
  showToast('Analyse termin\xe9e \u2014 Niveau : '+aiData.threat_level,'success');
  document.getElementById('snum4').textContent='\u2713';
}

function renderAI(d){
  document.getElementById('analysisResult').style.display='block';
  const badge=document.getElementById('threatBadge');
  badge.textContent=d.threat_level||'\u2014';
  badge.className='threat-badge threat-'+(d.threat_level||'BENIN');
  document.getElementById('compromisedStatus').textContent='Compromission : '+(d.compromised||'\u2014');
  document.getElementById('engineName').textContent='Moteur : '+(d.engine||'\u2014')+' \xb7 '+(d.generated_at||'').slice(0,16).replace('T',' ');
  document.getElementById('execSummary').textContent=d.executive_summary||'\u2014';
  const mkItems=(arr,icon)=>(arr||[]).map(i=>'<div class="finding-item">'+icon+' '+esc(i)+'</div>').join('')||'<div style="color:var(--muted)">Aucun</div>';
  document.getElementById('keyFindings').innerHTML=mkItems(d.key_findings,'\uD83D\uDD0D');
  document.getElementById('suspProcs').innerHTML=mkItems(d.suspicious_processes,'\u2699\uFE0F');
  document.getElementById('suspNet').innerHTML=mkItems(d.suspicious_network,'\uD83C\uDF10');
  document.getElementById('persist').innerHTML=mkItems(d.persistence_mechanisms,'\uD83D\uDD12');
  document.getElementById('iocList').innerHTML=(d.iocs||[]).map(i=>'<div class="ioc-row"><span class="ioc-type">'+esc(i.type)+'</span><span style="font-family:var(--font-mono);font-size:12px">'+esc(i.value)+'</span><span style="font-size:11px;color:var(--muted);margin-left:8px">'+esc(i.desc)+'</span></div>').join('')||'<div style="color:var(--muted)">Aucun IOC</div>';
  document.getElementById('mitreList').innerHTML=(d.mitre_techniques||[]).map(m=>'<span class="mitre-pill" title="'+esc(m.desc)+'">'+esc(m.id)+' \xb7 '+esc(m.name)+'</span>').join('')||'<div style="color:var(--muted)">Aucune technique</div>';
  document.getElementById('timeline').innerHTML=(d.timeline||[]).map(t=>'<div class="timeline-item"><span class="timeline-time">'+esc(t.time)+'</span><div><div style="font-size:12px">'+esc(t.event)+'</div><div style="font-size:10px;color:var(--muted)">'+esc(t.source)+'</div></div></div>').join('')||'<div style="color:var(--muted)">Aucune timeline</div>';
  document.getElementById('recos').innerHTML=mkItems(d.recommendations,'\u25B6');
}

// ── Etape 5 : Rapport ────────────────────────────────────────────────────────
function refreshReportSummary(){
  const el=document.getElementById('reportSummary');
  if(!aiData){ el.innerHTML='<div style="color:var(--muted);font-size:13px">Revenez \xe0 l\u2019\xe9tape 4 pour lancer l\u2019analyse IA</div>'; return; }
  const d=aiData;
  el.innerHTML='<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap"><div class="threat-badge threat-'+(d.threat_level||'BENIN')+'" style="font-size:14px">'+(d.threat_level||'\u2014')+'</div><div><div style="font-weight:700">'+(d.hostname||'\u2014')+'</div><div style="font-size:12px;color:var(--muted)">'+(d.engine||'\u2014')+' \xb7 '+(d.iocs||[]).length+' IOCs \xb7 '+(d.mitre_techniques||[]).length+' MITRE</div></div></div><p style="margin-top:10px;font-size:13px;line-height:1.6">'+(d.executive_summary||'').slice(0,250)+'...</p>';
}

async function downloadReport(){
  if(!selColId){ showToast('Aucune analyse disponible','warn'); return; }
  const btn=document.getElementById('btnDl');
  btn.disabled=true;
  showToast('G\xe9n\xe9ration du rapport en cours...','info');
  try{
    const r=await fetch('/api/report/export?id='+selColId);
    if(!r.ok){ showToast('Erreur lors de la g\xe9n\xe9ration','error'); return; }
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    const cd=r.headers.get('Content-Disposition');
    let fn='rapport_forensique.docx';
    if(cd){ const m=cd.match(/filename="([^"]+)"/); if(m) fn=m[1]; }
    a.href=url; a.download=fn; document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Rapport t\xe9l\xe9charg\xe9 : '+fn,'success');
    document.getElementById('snum5').textContent='\u2713';
  }catch(e){ showToast('Erreur : '+e.message,'error'); }
  btn.disabled=false;
}

function startOver(){
  selColId=null; selColInfo=null; aiData=null;
  for(let i=1;i<=5;i++) document.getElementById('snum'+i).textContent=i;
  goStep(1); showToast('Pr\xeat pour une nouvelle analyse','info');
}

// ── Log window ───────────────────────────────────────────────────────────────
let logOpen=false,logSSE=null,logCnt=0;
function toggleLog(){
  const win=document.getElementById('logWindow'),btn=document.getElementById('logBtn');
  logOpen=!logOpen; win.classList.toggle('open',logOpen); btn.classList.toggle('active',logOpen);
  if(logOpen&&!logSSE) startLogSSE();
}
function colorLog(l){
  if(l.includes('[BUILD-VELO]')||l.includes('[BUILD]')) return 'lbuild';
  if(l.includes('[COLLECTOR]')||l.includes('[VELO]')) return 'lcol';
  if(l.includes('[IA]')) return 'lia';
  if(l.includes('WARN')||l.includes('[!]')||l.includes('ERREUR')) return 'lwarn';
  if(l.includes('ERROR')||l.includes('[FAIL]')) return 'lerr';
  return 'linfo';
}
function appendLog(line){
  if(!line.trim()) return;
  const el=document.getElementById('logContent');
  const div=document.createElement('div'); div.className='log-line '+colorLog(line); div.textContent=line; el.appendChild(div);
  if(el.scrollHeight-el.scrollTop-el.clientHeight<60) el.scrollTop=el.scrollHeight;
  logCnt++; const c=document.getElementById('logCnt'); if(c) c.textContent='('+logCnt+')';
  while(el.childElementCount>500) el.removeChild(el.firstChild);
}
function clearLogs(){ document.getElementById('logContent').innerHTML=''; logCnt=0; }
function startLogSSE(){ logSSE=new EventSource('/api/logs/stream'); logSSE.onmessage=e=>{ if(e.data&&!e.data.startsWith(':')) appendLog(e.data); }; }

// Drag log window
(function(){
  let dr=false,ox=0,oy=0;
  document.addEventListener('mousedown',e=>{const b=document.getElementById('logBar');if(!b||!b.contains(e.target))return;const w=document.getElementById('logWindow');if(!w)return;dr=true;const r=w.getBoundingClientRect();w.style.right='auto';w.style.bottom='auto';w.style.left=r.left+'px';w.style.top=r.top+'px';ox=e.clientX-r.left;oy=e.clientY-r.top;e.preventDefault();});
  document.addEventListener('mousemove',e=>{if(!dr)return;const w=document.getElementById('logWindow');if(!w)return;w.style.left=Math.max(0,Math.min(window.innerWidth-80,e.clientX-ox))+'px';w.style.top=Math.max(0,Math.min(window.innerHeight-40,e.clientY-oy))+'px';});
  document.addEventListener('mouseup',()=>{dr=false;});
})();
// Resize
(function(){
  let rs=false,sx=0,sy=0,sw=0,sh=0;
  document.addEventListener('mousedown',e=>{const h=document.getElementById('logResize');if(!h||!h.contains(e.target))return;const w=document.getElementById('logWindow');rs=true;sx=e.clientX;sy=e.clientY;sw=w.offsetWidth;sh=w.offsetHeight;e.preventDefault();});
  document.addEventListener('mousemove',e=>{if(!rs)return;const w=document.getElementById('logWindow');w.style.width=Math.max(320,sw+(e.clientX-sx))+'px';w.style.height=Math.max(140,sh+(e.clientY-sy))+'px';});
  document.addEventListener('mouseup',()=>{rs=false;});
})();

// ── Utils ────────────────────────────────────────────────────────────────────
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function showToast(msg,type='info'){
  let t=document.getElementById('_toast');
  if(!t){t=document.createElement('div');t.id='_toast';t.style.cssText='position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:11px 20px;border-radius:9px;font-size:13px;z-index:99999;max-width:480px;transition:opacity .3s;text-align:center';document.body.appendChild(t);}
  const cl={success:'#22c55e',error:'#ef4444',warn:'#f59e0b',info:'#00b4ff'};
  t.style.background='rgba(7,16,32,.97)';t.style.border='1px solid '+(cl[type]||'#00b4ff');t.style.color=cl[type]||'#c8daf0';t.style.opacity='1';t.textContent=msg;
  clearTimeout(t._t); t._t=setTimeout(()=>{t.style.opacity='0';},3500);
}

// ── Init ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded',()=>{
  detectVelo();
  loadArtifacts();
});
</script>
</body>
</html>
`
