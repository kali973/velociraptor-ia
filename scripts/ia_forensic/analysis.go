package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Structures du rapport forensique ────────────────────────────────────────

type ForensicReport struct {
	CollectionID     string        `json:"collection_id"`
	Hostname         string        `json:"hostname"`
	OSName           string        `json:"os_name"`
	Engine           string        `json:"engine"`
	ThreatLevel      string        `json:"threat_level"`
	Compromised      string        `json:"compromised"`
	ExecutiveSummary string        `json:"executive_summary"`
	KeyFindings      []string      `json:"key_findings"`
	SuspiciousProcs  []string      `json:"suspicious_processes"`
	SuspiciousNet    []string      `json:"suspicious_network"`
	Persistence      []string      `json:"persistence_mechanisms"`
	Timeline         []TimelineEvt `json:"timeline"`
	Recommendations  []string      `json:"recommendations"`
	IOCs             []ForensicIOC `json:"iocs"`
	MITRETechniques  []MITREEntry  `json:"mitre_techniques"`
	RawJSON          string        `json:"raw_json,omitempty"`
	GeneratedAt      string        `json:"generated_at"`
}

type TimelineEvt struct {
	Time   string `json:"time"`
	Event  string `json:"event"`
	Source string `json:"source"`
}

type ForensicIOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Desc  string `json:"desc"`
}

type MITREEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// ─── Moteur IA llama.cpp ──────────────────────────────────────────────────────

type llamaRequest struct {
	Model       string     `json:"model"`
	Messages    []llamaMsg `json:"messages"`
	Temperature float64    `json:"temperature"`
	MaxTokens   int        `json:"max_tokens"`
	Stream      bool       `json:"stream"`
}

type llamaMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type llamaResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func findLlamaServer(moteurDir string) string {
	exe, _ := os.Executable()
	candidates := []string{
		filepath.Join(moteurDir, "llama-server.exe"),
		filepath.Join(filepath.Dir(exe), "..", "moteur", "llama-server.exe"),
		filepath.Join(filepath.Dir(exe), "moteur", "llama-server.exe"),
		filepath.Join(os.Getenv("USERPROFILE"), "GolandProjects", "moteur", "llama-server.exe"),
		`moteur\llama-server.exe`,
	}
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				abs, _ := filepath.Abs(p)
				return abs
			}
		}
	}
	return ""
}

func findModel(llamaExe string) (path, name string) {
	dir := filepath.Join(filepath.Dir(llamaExe), "models")
	preferred := []struct{ file, name string }{
		{"mistral-7b-instruct-v0.2.Q4_K_M.gguf", "Mistral 7B"},
		{"Qwen2.5-14B-Instruct-Q4_K_M.gguf", "Qwen2.5 14B"},
	}
	for _, m := range preferred {
		p := filepath.Join(dir, m.file)
		if _, err := os.Stat(p); err == nil {
			return p, m.name
		}
	}
	// Fallback : premier .gguf trouvé
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".gguf") {
			return filepath.Join(dir, e.Name()), e.Name()
		}
	}
	return "", ""
}

var (
	llamaServerURL string
	llamaServerCmd interface{ Kill() error }
	llamaServerMu  sync.Mutex
)

func ensureLlamaServer(llamaExe, modelPath string) (string, error) {
	llamaServerMu.Lock()
	defer llamaServerMu.Unlock()

	baseURL := "http://127.0.0.1:11434"

	// Vérifier si déjà en cours
	resp, err := http.Get(baseURL + "/health")
	if err == nil {
		resp.Body.Close()
		log.Printf("[IA] llama-server déjà actif sur %s", baseURL)
		return baseURL, nil
	}

	log.Printf("[IA] Démarrage llama-server : %s", filepath.Base(modelPath))
	cmd := newCommand(llamaExe,
		"--model", modelPath,
		"--port", "11434",
		"--host", "127.0.0.1",
		"--ctx-size", "8192",
		"--n-gpu-layers", "99",
		"--threads", "4",
		"--log-disable",
	)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("démarrage llama-server : %w", err)
	}

	// Attendre prêt (max 90s)
	for i := 0; i < 90; i++ {
		time.Sleep(1 * time.Second)
		resp, err := http.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			log.Printf("[IA] llama-server prêt (%ds)", i+1)
			return baseURL, nil
		}
		if i%15 == 14 {
			log.Printf("[IA] En attente du serveur IA... (%ds)", i+1)
		}
	}
	cmd.Process.Kill()
	return "", fmt.Errorf("llama-server n'a pas répondu en 90s")
}

func callLlama(baseURL, prompt, modelName string) (string, error) {
	req := llamaRequest{
		Model: "local",
		Messages: []llamaMsg{
			{
				Role:    "system",
				Content: "Tu es un analyste DFIR senior. Réponds UNIQUEMENT en JSON valide sans markdown ni texte autour.",
			},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		MaxTokens:   2000,
		Stream:      false,
	}
	data, _ := json.Marshal(req)

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Post(baseURL+"/v1/chat/completions", "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("appel llama API : %w", err)
	}
	defer resp.Body.Close()

	var llResp llamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&llResp); err != nil {
		return "", fmt.Errorf("décodage réponse : %w", err)
	}
	if len(llResp.Choices) == 0 {
		return "", fmt.Errorf("réponse vide du modèle")
	}
	return llResp.Choices[0].Message.Content, nil
}

// buildForensicPrompt construit le prompt IA à partir des données de collecte.
func buildForensicPrompt(parsed *ParsedCollection) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Hôte analysé : %s (OS: %s)\n", parsed.Hostname, parsed.OSName))
	sb.WriteString(fmt.Sprintf("Nombre d'artefacts collectés : %d\n\n", len(parsed.Artifacts)))

	// Résumé compact de chaque artefact (max 20 lignes par artefact)
	for _, art := range parsed.Artifacts {
		if len(art.Rows) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("=== %s (%d entrées) ===\n", art.Name, len(art.Rows)))
		limit := len(art.Rows)
		if limit > 20 {
			limit = 20
		}
		for i, row := range art.Rows[:limit] {
			// Sérialiser chaque ligne de façon compacte
			compact, _ := json.Marshal(row)
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, string(compact)))
		}
		if len(art.Rows) > 20 {
			sb.WriteString(fmt.Sprintf("  ... et %d autres entrées\n", len(art.Rows)-20))
		}
		sb.WriteString("\n")
	}

	schema := `{
  "threat_level": "CRITIQUE|ELEVE|MOYEN|FAIBLE|BENIN",
  "compromised": "CONFIRME|PROBABLE|SUSPECTE|NON_DETECTE",
  "executive_summary": "Résumé en 4-5 phrases pour le management",
  "key_findings": ["Découverte 1", "Découverte 2"],
  "suspicious_processes": ["processus.exe - raison"],
  "suspicious_network": ["ip:port - contexte"],
  "persistence_mechanisms": ["mécanisme de persistance détecté"],
  "timeline": [{"time":"HH:MM","event":"description","source":"artefact"}],
  "recommendations": ["Action 1 immédiate", "Action 2 dans 24h"],
  "iocs": [{"type":"IP|HASH|DOMAIN|FILE","value":"valeur","desc":"contexte"}],
  "mitre_techniques": [{"id":"TXXXX","name":"nom technique","desc":"observation"}]
}`

	return fmt.Sprintf(
		"Analyse ces données de collecte forensique Velociraptor et génère un rapport DFIR en JSON :\n%s\n\nDonnées de collecte :\n%s\n\nRéponds UNIQUEMENT avec le JSON valide.",
		schema, sb.String())
}

// parseForensicJSON extrait le ForensicReport du JSON renvoyé par l'IA.
func parseForensicJSON(raw string) *ForensicReport {
	// Nettoyer les backticks markdown
	clean := raw
	if idx := strings.Index(clean, "{"); idx > 0 {
		clean = clean[idx:]
	}
	if idx := strings.LastIndex(clean, "}"); idx >= 0 {
		clean = clean[:idx+1]
	}

	var report struct {
		ThreatLevel      string        `json:"threat_level"`
		Compromised      string        `json:"compromised"`
		ExecutiveSummary string        `json:"executive_summary"`
		KeyFindings      []string      `json:"key_findings"`
		SuspiciousProcs  []string      `json:"suspicious_processes"`
		SuspiciousNet    []string      `json:"suspicious_network"`
		Persistence      []string      `json:"persistence_mechanisms"`
		Timeline         []TimelineEvt `json:"timeline"`
		Recommendations  []string      `json:"recommendations"`
		IOCs             []ForensicIOC `json:"iocs"`
		MITRETechniques  []MITREEntry  `json:"mitre_techniques"`
	}

	if err := json.Unmarshal([]byte(clean), &report); err != nil {
		return &ForensicReport{RawJSON: raw}
	}

	return &ForensicReport{
		ThreatLevel:      report.ThreatLevel,
		Compromised:      report.Compromised,
		ExecutiveSummary: report.ExecutiveSummary,
		KeyFindings:      report.KeyFindings,
		SuspiciousProcs:  report.SuspiciousProcs,
		SuspiciousNet:    report.SuspiciousNet,
		Persistence:      report.Persistence,
		Timeline:         report.Timeline,
		Recommendations:  report.Recommendations,
		IOCs:             report.IOCs,
		MITRETechniques:  report.MITRETechniques,
	}
}

// ─── Analyse IA complète ──────────────────────────────────────────────────────

var (
	analysisMu      sync.Mutex
	analysisRunning bool
	analysisDone    bool
	analysisResult  *ForensicReport
	analysisErr     string
)

func runAnalysis(collectionID, zipPath string, cfg *Config) {
	defer func() {
		analysisMu.Lock()
		analysisRunning = false
		analysisDone = true
		analysisMu.Unlock()
	}()

	// Parser le ZIP
	log.Printf("[IA] Parsing de la collecte : %s", zipPath)
	parsed, err := parseVelociraptorZIP(zipPath)
	if err != nil {
		log.Printf("[IA] ERREUR parsing ZIP : %v", err)
		analysisMu.Lock()
		analysisErr = fmt.Sprintf("Erreur parsing ZIP : %v", err)
		analysisMu.Unlock()
		return
	}
	log.Printf("[IA] Collecte parsée : %s / %s / %d artefacts",
		parsed.Hostname, parsed.OSName, len(parsed.Artifacts))

	// Trouver le moteur IA
	llamaExe := findLlamaServer(cfg.MoteurDir)
	if llamaExe == "" {
		log.Printf("[IA] llama-server.exe introuvable, analyse IA impossible")
		analysisMu.Lock()
		analysisErr = "llama-server.exe introuvable. Installez le moteur IA via scripts/setup_moteur.ps1"
		analysisMu.Unlock()
		return
	}

	modelPath, modelName := findModel(llamaExe)
	if modelPath == "" {
		log.Printf("[IA] Aucun modèle GGUF trouvé dans moteur/models/")
		analysisMu.Lock()
		analysisErr = "Aucun modèle GGUF trouvé. Lancez setup_moteur.ps1"
		analysisMu.Unlock()
		return
	}
	log.Printf("[IA] Modèle sélectionné : %s", modelName)

	// Démarrer/réutiliser llama-server
	baseURL, err := ensureLlamaServer(llamaExe, modelPath)
	if err != nil {
		log.Printf("[IA] ERREUR démarrage serveur IA : %v", err)
		analysisMu.Lock()
		analysisErr = fmt.Sprintf("Démarrage moteur IA échoué : %v", err)
		analysisMu.Unlock()
		return
	}

	// Construire et envoyer le prompt
	prompt := buildForensicPrompt(parsed)
	log.Printf("[IA] Envoi du prompt forensique (%d artefacts, ~%d caractères)...",
		len(parsed.Artifacts), len(prompt))

	rawResponse, err := callLlama(baseURL, prompt, modelName)
	if err != nil {
		log.Printf("[IA] ERREUR appel API : %v", err)
		analysisMu.Lock()
		analysisErr = fmt.Sprintf("Appel API IA échoué : %v", err)
		analysisMu.Unlock()
		return
	}

	log.Printf("[IA] Réponse reçue (%d caractères), parsing...", len(rawResponse))

	report := parseForensicJSON(rawResponse)
	if report == nil {
		report = &ForensicReport{RawJSON: rawResponse}
	}
	report.CollectionID = collectionID
	report.Hostname = parsed.Hostname
	report.OSName = parsed.OSName
	report.Engine = modelName
	report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	log.Printf("[IA] ✓ Analyse terminée — Niveau : %s | Compromis : %s",
		report.ThreatLevel, report.Compromised)

	// Sauvegarder en DB
	findingsJSON, _ := json.Marshal(report.KeyFindings)
	iocsJSON, _ := json.Marshal(report.IOCs)
	mitreJSON, _ := json.Marshal(report.MITRETechniques)
	timelineJSON, _ := json.Marshal(report.Timeline)
	recoJSON, _ := json.Marshal(report.Recommendations)

	dbMu.Lock()
	if db != nil {
		_, _ = db.Exec(`INSERT OR REPLACE INTO analyses
			(collection_id, engine, threat_level, summary, findings, iocs, mitre, timeline, recommendations, report_path, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			collectionID, modelName, report.ThreatLevel, report.ExecutiveSummary,
			string(findingsJSON), string(iocsJSON), string(mitreJSON),
			string(timelineJSON), string(recoJSON), "", report.GeneratedAt)
	}
	dbMu.Unlock()

	// Mettre à jour le status de la collection
	dbMu.Lock()
	if db != nil {
		_, _ = db.Exec(`UPDATE collections SET status='analysed' WHERE id=?`, collectionID)
	}
	dbMu.Unlock()

	analysisMu.Lock()
	analysisResult = report
	analysisMu.Unlock()
}
