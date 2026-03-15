package main

import (
	"archive/zip"
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

// findVelociraptorBin cherche le binaire Velociraptor.
// Sur Windows, seuls les fichiers .exe sont retournés (exec.Command
// échoue avec un chemin absolu sans extension sur Windows).
func findVelociraptorBin(cfgPath string) string {
	isWindows := strings.EqualFold(os.Getenv("OS"), "Windows_NT") ||
		strings.Contains(strings.ToLower(os.Getenv("COMSPEC")), "cmd.exe") ||
		os.PathSeparator == '\\'

	validate := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return ""
		}
		if _, err := os.Stat(abs); err != nil {
			return ""
		}
		// Sur Windows, refuser un chemin sans .exe
		if isWindows && !strings.HasSuffix(strings.ToLower(abs), ".exe") {
			// Essayer avec .exe
			withExt := abs + ".exe"
			if _, err2 := os.Stat(withExt); err2 == nil {
				return withExt
			}
			return "" // sans .exe non exécutable par chemin absolu sur Windows
		}
		return abs
	}

	// 1. Chemin explicite (config ou champ UI)
	if cfgPath != "" {
		if v := validate(cfgPath); v != "" {
			return v
		}
	}

	// 2. Dossier output/ produit par : go run make.go -v windowsDev
	//    Deux noms possibles selon la version de make.go :
	//      - output/velociraptor.exe            (nom court)
	//      - output/velociraptor-vX.Y.Z-windows-amd64.exe  (nom versionné)
	for _, base := range []string{".", "..", "../..", "../../.."} {
		outDir := filepath.Join(base, "output")

		// Nom court en priorité (c'est ce que make.go -v windowsDev produit)
		if v := validate(filepath.Join(outDir, "velociraptor.exe")); v != "" {
			return v
		}

		// Nom versionné
		entries, err := os.ReadDir(outDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := strings.ToLower(e.Name())
			if strings.HasPrefix(n, "velociraptor") &&
				strings.Contains(n, "windows") &&
				strings.HasSuffix(n, ".exe") {
				if v := validate(filepath.Join(outDir, e.Name())); v != "" {
					return v
				}
			}
		}
	}

	// 3. Binaires à la racine du projet (téléchargé manuellement)
	var candidates []string
	if isWindows {
		candidates = []string{
			"velociraptor.exe",
			"velociraptor-windows-amd64.exe",
		}
	} else {
		candidates = []string{
			"velociraptor",
			"velociraptor-linux-amd64",
			"velociraptor.exe",
		}
	}
	for _, base := range []string{".", "..", "../..", "../../.."} {
		for _, name := range candidates {
			if v := validate(filepath.Join(base, name)); v != "" {
				return v
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

	// ── Résoudre le binaire ──────────────────────────────────────────────────
	binPath := findVelociraptorBin(req.VeloPath)
	if binPath == "" {
		binPath = findVelociraptorBin(cfg.VeloRaptorBin)
	}
	if binPath == "" {
		addOutput("[ERREUR] velociraptor.exe introuvable.")
		addOutput("[INFO] Compilez-le via le bouton 'Compiler velociraptor.exe' ou téléchargez-le depuis GitHub Releases.")
		buildMu.Lock()
		buildSuccess = false
		buildMu.Unlock()
		return
	}
	addOutput(fmt.Sprintf("[COLLECTOR] Binaire : %s", binPath))

	// ── Préparer le dossier de sortie ────────────────────────────────────────
	outDir := cfg.OutputDir
	if req.OutputDir != "" {
		outDir = req.OutputDir
	}
	absOutDir, _ := filepath.Abs(outDir)
	_ = os.MkdirAll(absOutDir, 0755)

	targetOS := req.TargetOS
	if targetOS == "" {
		targetOS = "windows"
	}

	ts := time.Now().Format("20060102_150405")
	zipOut := filepath.Join(absOutDir, fmt.Sprintf("Collection_%s_%s.zip", targetOS, ts))

	addOutput(fmt.Sprintf("[COLLECTOR] Démarrage : %d artefact(s), cible=%s", len(req.Artifacts), targetOS))
	addOutput(fmt.Sprintf("[COLLECTOR] Sortie ZIP : %s", zipOut))

	// ── Syntaxe correcte Velociraptor pour collecte locale ───────────────────
	//
	// velociraptor.exe artifacts collect \
	//   --output /path/to/output_dir \
	//   --format jsonl \
	//   ArtifactName1 ArtifactName2 ...
	//
	// Le répertoire de sortie est créé par Velociraptor.
	// Pour récupérer un ZIP on pointe --output vers un dossier temporaire
	// puis on zippe nous-mêmes, OU on utilise le mode "collector" :
	//
	// velociraptor.exe collector \
	//   --definitions artifact1,artifact2 \
	//   --output zippath.zip
	//
	// On essaie les deux modes en fallback.

	// ── Mode 1 : artifacts collect (collecte directe, sortie répertoire) ─────
	collectDir := filepath.Join(absOutDir, fmt.Sprintf("col_%s", ts))
	_ = os.MkdirAll(collectDir, 0755)

	args1 := append([]string{
		"artifacts", "collect",
		"--output", collectDir,
		"--format", "jsonl",
	}, req.Artifacts...)

	addOutput(fmt.Sprintf("[COLLECTOR] Commande : %s artifacts collect --output %s --format jsonl [%d artefacts]",
		filepath.Base(binPath), collectDir, len(req.Artifacts)))

	cmd1 := exec.Command(binPath, args1...)
	out1 := &lineCollector{}
	cmd1.Stdout = out1
	cmd1.Stderr = out1

	err1 := cmd1.Run()
	for _, l := range out1.lines {
		if l != "" {
			addOutput("[VELO] " + l)
		}
	}

	if err1 == nil {
		// Vérifier que des fichiers ont été créés
		if hasFiles(collectDir) {
			// Zipper le dossier de collecte
			if zipErr := zipDirectory(collectDir, zipOut); zipErr == nil {
				_ = os.RemoveAll(collectDir)
				addOutput(fmt.Sprintf("[COLLECTOR] ✓ Collection ZIP : %s", zipOut))
				buildMu.Lock()
				buildSuccess = true
				buildResult = zipOut
				buildMu.Unlock()
				return
			}
			// ZIP échoué mais le dossier existe
			addOutput(fmt.Sprintf("[COLLECTOR] ✓ Collection (dossier) : %s", collectDir))
			buildMu.Lock()
			buildSuccess = true
			buildResult = collectDir
			buildMu.Unlock()
			return
		}
		addOutput("[COLLECTOR] Mode 1 : commande OK mais aucun fichier produit")
	} else {
		addOutput(fmt.Sprintf("[COLLECTOR] Mode 1 échoué : %v", err1))
	}
	_ = os.RemoveAll(collectDir)

	// ── Mode 2 : velociraptor gui collector (Build Offline Collector) ─────────
	// Génère un executable collector autonome via l'API REST
	// → non disponible en ligne de commande directe, skip

	// ── Mode 3 : velociraptor collector --config yaml ─────────────────────────
	yamlContent := buildCollectorYAML(req.Artifacts, targetOS)
	yamlPath := filepath.Join(absOutDir, fmt.Sprintf("collector_config_%s.yaml", ts))
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0600); err == nil {
		defer os.Remove(yamlPath)

		args3 := []string{
			"collector", "--config", yamlPath,
			"--output", zipOut,
		}
		addOutput(fmt.Sprintf("[COLLECTOR] Mode 3 : velociraptor collector --config %s", filepath.Base(yamlPath)))

		cmd3 := exec.Command(binPath, args3...)
		out3 := &lineCollector{}
		cmd3.Stdout = out3
		cmd3.Stderr = out3

		err3 := cmd3.Run()
		for _, l := range out3.lines {
			if l != "" {
				addOutput("[VELO] " + l)
			}
		}

		if err3 == nil {
			if _, statErr := os.Stat(zipOut); statErr == nil {
				addOutput(fmt.Sprintf("[COLLECTOR] ✓ Collection ZIP (mode collector) : %s", zipOut))
				buildMu.Lock()
				buildSuccess = true
				buildResult = zipOut
				buildMu.Unlock()
				return
			}
		}
		addOutput(fmt.Sprintf("[COLLECTOR] Mode 3 échoué : %v", err3))
	}

	// ── Aucun mode n'a fonctionné ─────────────────────────────────────────────
	addOutput("[ERREUR] Tous les modes de collecte ont échoué.")
	addOutput("[INFO] Lancez la collecte manuellement depuis Velociraptor GUI (bouton 'Ouvrir Velociraptor GUI')")
	addOutput("[INFO] puis importez le ZIP obtenu à l'Étape 2.")
	buildMu.Lock()
	buildSuccess = false
	buildMu.Unlock()
}

// buildCollectorYAML génère un YAML de configuration pour velociraptor collector.
func buildCollectorYAML(artifacts []string, targetOS string) string {
	var sb strings.Builder
	sb.WriteString("autoexec:\n")
	sb.WriteString("  argv:\n")
	sb.WriteString("  - artifacts\n")
	sb.WriteString("  - collect\n")
	sb.WriteString("  - --format\n")
	sb.WriteString("  - jsonl\n")
	for _, a := range artifacts {
		sb.WriteString(fmt.Sprintf("  - %s\n", a))
	}
	sb.WriteString(fmt.Sprintf("# target_os: %s\n", targetOS))
	return sb.String()
}

// lineCollector collecte les lignes de sortie d'une commande.
type lineCollector struct {
	lines []string
	buf   string
}

func (lc *lineCollector) Write(p []byte) (int, error) {
	lc.buf += string(p)
	for {
		idx := strings.IndexByte(lc.buf, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(lc.buf[:idx], "\r")
		lc.lines = append(lc.lines, line)
		lc.buf = lc.buf[idx+1:]
	}
	return len(p), nil
}

// hasFiles retourne true si le répertoire contient au moins un fichier.
func hasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// zipDirectory crée un ZIP du contenu d'un répertoire.
func zipDirectory(srcDir, destZip string) error {
	zf, err := os.Create(destZip)
	if err != nil {
		return err
	}
	defer zf.Close()

	w := zip.NewWriter(zf)
	defer w.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(srcDir, path)
		fw, err := w.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		buf := make([]byte, 32*1024)
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, wErr := fw.Write(buf[:n]); wErr != nil {
					return wErr
				}
			}
			if readErr != nil {
				break
			}
		}
		return nil
	})
}
