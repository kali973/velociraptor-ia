package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Artefacts disponibles ────────────────────────────────────────────────────

type ArtifactGroup struct {
	Name      string   `json:"name"`
	Label     string   `json:"label"`
	Artifacts []string `json:"artifacts"`
	Icon      string   `json:"icon"`
}

var ArtifactCatalog = []ArtifactGroup{
	{
		Name:  "processes",
		Label: "Processus & Services",
		Icon:  "⚙️",
		Artifacts: []string{
			"Windows.System.Pslist",
			"Windows.System.Services",
			"Windows.System.TaskScheduler",
			"Windows.System.Autoruns",
			"Windows.System.DLLHijacking",
		},
	},
	{
		Name:  "network",
		Label: "Réseau",
		Icon:  "🌐",
		Artifacts: []string{
			"Windows.Network.Netstat",
			"Windows.Network.ArpCache",
			"Windows.Network.InterfaceAddresses",
			"Windows.Network.Hosts",
			"Windows.Network.ListeningPorts",
		},
	},
	{
		Name:  "filesystem",
		Label: "Système de fichiers",
		Icon:  "📂",
		Artifacts: []string{
			"Windows.KapeFiles.Targets",
			"Windows.Forensics.Prefetch",
			"Windows.Forensics.RecentDocs",
			"Windows.Forensics.Lnk",
			"Windows.Forensics.SRUM",
			"Windows.Forensics.Shellbags",
			"Windows.Forensics.Jumplists",
		},
	},
	{
		Name:  "registry",
		Label: "Registre Windows",
		Icon:  "🔑",
		Artifacts: []string{
			"Windows.Registry.UserAssist",
			"Windows.Registry.Run",
			"Windows.Registry.NTUser",
			"Windows.Registry.Sysinternals.Eulacheck",
			"Windows.Registry.AppCompatCache",
		},
	},
	{
		Name:  "eventlogs",
		Label: "Journaux d'événements",
		Icon:  "📋",
		Artifacts: []string{
			"Windows.EventLogs.Evtx",
			"Windows.EventLogs.RDPAuth",
			"Windows.EventLogs.PowershellModule",
			"Windows.EventLogs.BITS",
			"Windows.EventLogs.AlternateLogon",
		},
	},
	{
		Name:  "memory",
		Label: "Mémoire & Injections",
		Icon:  "🧠",
		Artifacts: []string{
			"Windows.Memory.ProcessInfo",
			"Windows.Detection.HollowProcess",
			"Windows.Detection.LsaTools",
			"Windows.Detection.Malfind",
		},
	},
	{
		Name:  "users",
		Label: "Utilisateurs & Authentification",
		Icon:  "👥",
		Artifacts: []string{
			"Windows.Sys.AllUsers",
			"Windows.Sys.LoggedInUsers",
			"Windows.EventLogs.RDPAuth",
			"Windows.Forensics.SAM",
		},
	},
	{
		Name:  "ir_complet",
		Label: "Réponse à incident (collecte complète)",
		Icon:  "🚨",
		Artifacts: []string{
			"Windows.Triage.Collection",
			"Windows.KapeFiles.Targets",
			"Generic.Collectors.Profile",
		},
	},
}

// ─── Détection du binaire Velociraptor ───────────────────────────────────────

// findVelociraptorBin cherche le binaire Velociraptor dans :
//  1. Le chemin explicite passé en config
//  2. ./output/  (produit par make windows / go run make.go)
//  3. La racine du projet (binaire téléchargé manuellement)
//
// La commande de build du projet est : make windows → go run make.go -v windowsDev
// Cela produit output/velociraptor-vX.Y.Z-windows-amd64.exe
func findVelociraptorBin(cfgPath string) string {
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); err == nil {
			abs, _ := filepath.Abs(cfgPath)
			return abs
		}
	}

	// Chercher dans output/ (résultat de make windows)
	for _, base := range []string{".", "..", "../.."} {
		outDir := filepath.Join(base, "output")
		if entries, err := os.ReadDir(outDir); err == nil {
			for _, e := range entries {
				n := strings.ToLower(e.Name())
				if strings.HasPrefix(n, "velociraptor") &&
					strings.Contains(n, "windows") &&
					strings.HasSuffix(n, ".exe") {
					abs, _ := filepath.Abs(filepath.Join(outDir, e.Name()))
					return abs
				}
			}
		}
	}

	// Fallback : binaires génériques à la racine
	for _, base := range []string{".", "..", "../.."} {
		for _, name := range []string{
			"velociraptor.exe",
			"velociraptor-windows-amd64.exe",
			"velociraptor",
		} {
			p := filepath.Join(base, name)
			if _, err := os.Stat(p); err == nil {
				abs, _ := filepath.Abs(p)
				return abs
			}
		}
	}
	return ""
}

// ─── Build du collector ───────────────────────────────────────────────────────

type CollectorRequest struct {
	Artifacts []string `json:"artifacts"`
	TargetOS  string   `json:"target_os"`
	OutputDir string   `json:"output_dir"`
	VeloPath  string   `json:"velo_path"`
}

var (
	buildMu      sync.Mutex
	buildRunning bool
	buildDone    bool
	buildSuccess bool
	buildOutput  []string
	buildResult  string
)

func runBuildCollector(req CollectorRequest, cfg *Config) {
	defer func() {
		buildMu.Lock()
		buildRunning = false
		buildDone = true
		buildMu.Unlock()
	}()

	addOutput := func(msg string) {
		log.Print(msg)
		buildMu.Lock()
		buildOutput = append(buildOutput, msg)
		buildMu.Unlock()
	}

	binPath := findVelociraptorBin(req.VeloPath)
	if binPath == "" {
		binPath = findVelociraptorBin(cfg.VeloRaptorBin)
	}
	if binPath == "" {
		addOutput("[ERREUR] velociraptor.exe introuvable. Placez-le dans le dossier du projet ou configurez le chemin dans la config.")
		buildMu.Lock()
		buildSuccess = false
		buildMu.Unlock()
		return
	}
	addOutput(fmt.Sprintf("[COLLECTOR] Binaire Velociraptor : %s", binPath))

	outDir := cfg.OutputDir
	if req.OutputDir != "" {
		outDir = req.OutputDir
	}
	_ = os.MkdirAll(outDir, 0755)

	targetOS := req.TargetOS
	if targetOS == "" {
		targetOS = "windows"
	}

	addOutput(fmt.Sprintf("[COLLECTOR] Démarrage : %d artefact(s), cible=%s", len(req.Artifacts), targetOS))

	// Construire les arguments velociraptor
	// Mode : velociraptor.exe artifacts collect --output <zip> <artifact1> <artifact2> ...
	// Ou en mode offline collector :
	// velociraptor.exe artifacts collect --output <dir> --format=jsonl <artifacts...>
	ts := time.Now().Format("20060102_150405")
	ext := ".exe"
	if targetOS != "windows" {
		ext = ""
	}

	// Tentative avec la commande "artifacts collect" (collecte locale)
	collectorOut := filepath.Join(outDir, fmt.Sprintf("Collection_%s_%s%s", targetOS, ts, ext))
	zipOut := filepath.Join(outDir, fmt.Sprintf("Collection_%s_%s.zip", targetOS, ts))

	// D'abord essayer de construire un offline collector
	args := []string{
		"artifacts", "collect",
		"--output", zipOut,
		"--format", "jsonl",
	}
	args = append(args, req.Artifacts...)

	addOutput(fmt.Sprintf("[COLLECTOR] Commande : %s %s", filepath.Base(binPath), strings.Join(args[:4], " ")+" [artefacts...]"))

	cmd := exec.Command(binPath, args...)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	err := cmd.Run()
	output := outBuf.String()

	if output != "" {
		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			if line != "" {
				addOutput("[VELO] " + line)
			}
		}
	}

	if err != nil {
		// Fallback : essayer de construire un collector standalone
		addOutput("[COLLECTOR] Mode artifacts collect échoué, tentative offline collector...")
		args2 := []string{
			"artifacts", "collect",
			"--output", collectorOut,
		}
		args2 = append(args2, req.Artifacts...)
		cmd2 := exec.Command(binPath, args2...)
		var out2 bytes.Buffer
		cmd2.Stdout = &out2
		cmd2.Stderr = &out2
		err2 := cmd2.Run()
		out2Str := out2.String()
		for _, line := range strings.Split(strings.TrimSpace(out2Str), "\n") {
			if line != "" {
				addOutput("[VELO] " + line)
			}
		}
		if err2 != nil {
			addOutput(fmt.Sprintf("[ERREUR] Velociraptor a échoué : %v", err2))
			addOutput("[INFO] Assurez-vous que velociraptor.exe peut accéder aux artefacts demandés.")
			addOutput("[INFO] Certains artefacts nécessitent des droits administrateur.")
			buildMu.Lock()
			buildSuccess = false
			buildMu.Unlock()
			return
		}
		buildMu.Lock()
		buildSuccess = true
		buildResult = collectorOut
		buildMu.Unlock()
		addOutput(fmt.Sprintf("[COLLECTOR] ✓ Collection générée : %s", collectorOut))
		return
	}

	// Vérifier que le ZIP a été créé
	if _, err := os.Stat(zipOut); err == nil {
		buildMu.Lock()
		buildSuccess = true
		buildResult = zipOut
		buildMu.Unlock()
		addOutput(fmt.Sprintf("[COLLECTOR] ✓ Collection ZIP générée : %s", zipOut))
	} else {
		buildMu.Lock()
		buildSuccess = true
		buildResult = outDir
		buildMu.Unlock()
		addOutput(fmt.Sprintf("[COLLECTOR] ✓ Collection dans : %s", outDir))
	}
}
