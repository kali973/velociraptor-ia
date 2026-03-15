package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DocxPayload est la charge envoyée à docx_gen.js pour la génération du rapport.
type DocxPayload struct {
	Report    *ForensicReport `json:"report"`
	Generated string          `json:"generated"`
}

// handleExportReport génère le rapport DOCX via docx_gen.js ou fallback TXT/JSON.
func handleExportReport(w http.ResponseWriter, r *http.Request) {
	collectionID := r.URL.Query().Get("id")
	if collectionID == "" {
		http.Error(w, `{"error":"id manquant"}`, http.StatusBadRequest)
		return
	}

	// Récupérer le rapport depuis la DB
	var report ForensicReport
	dbMu.Lock()
	if db != nil {
		var findingsStr, iocsStr, mitreStr, timelineStr, recoStr string
		err := db.QueryRow(`
			SELECT a.engine, a.threat_level, a.summary, a.findings, a.iocs, a.mitre,
			       a.timeline, a.recommendations, a.created_at,
			       c.hostname, c.os_name
			FROM analyses a
			JOIN collections c ON c.id = a.collection_id
			WHERE a.collection_id = ?`, collectionID).Scan(
			&report.Engine, &report.ThreatLevel, &report.ExecutiveSummary,
			&findingsStr, &iocsStr, &mitreStr, &timelineStr, &recoStr, &report.GeneratedAt,
			&report.Hostname, &report.OSName,
		)
		if err == nil {
			_ = json.Unmarshal([]byte(findingsStr), &report.KeyFindings)
			_ = json.Unmarshal([]byte(iocsStr), &report.IOCs)
			_ = json.Unmarshal([]byte(mitreStr), &report.MITRETechniques)
			_ = json.Unmarshal([]byte(timelineStr), &report.Timeline)
			_ = json.Unmarshal([]byte(recoStr), &report.Recommendations)
			report.CollectionID = collectionID
		}
	}
	dbMu.Unlock()

	if report.ThreatLevel == "" && report.ExecutiveSummary == "" {
		// Essayer le résultat en mémoire
		analysisMu.Lock()
		if analysisResult != nil && analysisResult.CollectionID == collectionID {
			report = *analysisResult
		}
		analysisMu.Unlock()
	}

	if report.ThreatLevel == "" {
		http.Error(w, `{"error":"aucune analyse disponible pour cette collection"}`, http.StatusNotFound)
		return
	}

	cfgMu.RLock()
	reportsDir := currentCfg.ReportsDir
	cfgMu.RUnlock()
	_ = os.MkdirAll(reportsDir, 0755)

	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("rapport_forensique_%s_%s", report.Hostname, ts)

	log.Printf("[RAPPORT] Génération rapport forensique : %s", filename)

	// Chercher docx_gen.js
	docxGenPath := findDocxGen()

	if docxGenPath != "" {
		// Générer le DOCX via docx_gen.js
		payload := DocxPayload{Report: &report, Generated: time.Now().UTC().Format(time.RFC3339)}
		tmpJSON := filepath.Join(reportsDir, fmt.Sprintf("report_tmp_%s.json", ts))
		tmpDOCX := filepath.Join(reportsDir, filename+".docx")
		defer os.Remove(tmpJSON)

		data, _ := json.Marshal(payload)
		if err := os.WriteFile(tmpJSON, data, 0600); err == nil {
			// Adapter le script docx_gen.js au format forensique
			genPath := filepath.Join(filepath.Dir(docxGenPath), "docx_forensic.js")
			if _, err2 := os.Stat(genPath); err2 != nil {
				genPath = docxGenPath // fallback sur docx_gen.js standard
			}

			cmd := exec.Command("node", genPath, tmpJSON, tmpDOCX)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				docxData, err2 := os.ReadFile(tmpDOCX)
				if err2 == nil {
					log.Printf("[RAPPORT] DOCX : %s (%d octets)", filename+".docx", len(docxData))
					w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
					w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.docx"`, filename))
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(docxData)))
					w.Write(docxData)
					os.Remove(tmpDOCX)
					return
				}
			} else {
				log.Printf("[RAPPORT] docx_gen.js erreur : %s", stderr.String())
			}
		}
	}

	// Fallback : rapport JSON structuré
	log.Printf("[RAPPORT] Fallback JSON (docx_gen.js introuvable ou erreur)")
	jsonPath := filepath.Join(reportsDir, filename+".json")
	data, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(jsonPath, data, 0644)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)

	log.Printf("[RAPPORT] ✓ Rapport JSON : %s", filepath.Base(jsonPath))
}

func findDocxGen() string {
	exe, _ := os.Executable()
	candidates := []string{
		"docx_gen.js",
		"../docx_gen.js",
		filepath.Join(filepath.Dir(exe), "docx_gen.js"),
		filepath.Join(filepath.Dir(exe), "..", "docx_gen.js"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}

// handleGetAnalysis retourne l'analyse stockée pour une collection.
func handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	collectionID := r.URL.Query().Get("id")
	if collectionID == "" {
		http.Error(w, `{"error":"id manquant"}`, http.StatusBadRequest)
		return
	}

	// Vérifier en mémoire d'abord
	analysisMu.Lock()
	if analysisResult != nil && analysisResult.CollectionID == collectionID {
		data, _ := json.Marshal(analysisResult)
		analysisMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	analysisMu.Unlock()

	// Chercher en DB
	var report ForensicReport
	dbMu.Lock()
	var found bool
	if db != nil {
		var findingsStr, iocsStr, mitreStr, timelineStr, recoStr string
		err := db.QueryRow(`
			SELECT a.engine, a.threat_level, a.summary, a.findings, a.iocs, a.mitre,
			       a.timeline, a.recommendations, a.created_at, c.hostname, c.os_name
			FROM analyses a
			JOIN collections c ON c.id = a.collection_id
			WHERE a.collection_id = ?`, collectionID).Scan(
			&report.Engine, &report.ThreatLevel, &report.ExecutiveSummary,
			&findingsStr, &iocsStr, &mitreStr, &timelineStr, &recoStr,
			&report.GeneratedAt, &report.Hostname, &report.OSName,
		)
		if err == nil {
			found = true
			_ = json.Unmarshal([]byte(findingsStr), &report.KeyFindings)
			_ = json.Unmarshal([]byte(iocsStr), &report.IOCs)
			_ = json.Unmarshal([]byte(mitreStr), &report.MITRETechniques)
			_ = json.Unmarshal([]byte(timelineStr), &report.Timeline)
			_ = json.Unmarshal([]byte(recoStr), &report.Recommendations)
			report.CollectionID = collectionID
		}
	}
	dbMu.Unlock()

	if !found {
		http.Error(w, `{"error":"aucune analyse trouvée"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(report)
	w.Write(data)
}

// newCommand est un helper pour exec.Command compatible cross-platform.
func newCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// Helpers pour affichage
func threatColor(level string) string {
	switch strings.ToUpper(level) {
	case "CRITIQUE":
		return "#ef4444"
	case "ELEVE", "ÉLEVÉ":
		return "#f59e0b"
	case "MOYEN":
		return "#eab308"
	case "FAIBLE":
		return "#22c55e"
	default:
		return "#6b7280"
	}
}

// logAnalysisProgress est appelé pendant l'analyse pour envoyer des mises à jour.
func logAnalysisProgress(msg string) {
	log.Printf("[IA] %s", msg)
}
