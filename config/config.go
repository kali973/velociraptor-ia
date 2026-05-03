// Package config charge et expose la configuration runtime depuis config.json.
//
// v0.4.0 : suppression de ClaudeAPIKey. Le projet est local-only.
// L'IA tourne sur llama-server local (cf. internal/engine), aucun appel
// reseau cloud n'est fait par velociraptor a partir de cette version.
//
//  1. config.json embarque (fallback) via go:embed.
//  2. config.json a cote de l'executable (override modifiable, prioritaire).
//  3. Dechiffrement transparent du HFToken (modeles HF gated optionnels).
package config

import (
	_ "embed"
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"velociraptor/vault"
)

//go:embed config.json
var configFile []byte

// AppConfig contient la configuration runtime.
type AppConfig struct {
	// Champs partages avec rf-sandbox-go (semantique identique pour faciliter
	// un eventuel merge ou partage de moteur).
	UIPort        string `json:"ui_port"`
	HFToken       string `json:"hf_token,omitempty"` // token HuggingFace pour modeles gated
	ListenAddress string `json:"listen_address,omitempty"`
	Lang          string `json:"lang,omitempty"`
	APIKey        string `json:"api_key,omitempty"` // Bearer pour /api/* (vide = pas d'auth)

	// Moteur IA local (v0.4.0)
	DefaultModel    string `json:"default_model,omitempty"`     // filename GGUF du modele par defaut
	AutoStartEngine bool   `json:"auto_start_engine,omitempty"` // demarre llama-server au boot

	// Champs propres a velociraptor
	VelociraptorArtifactsDir string `json:"velociraptor_artifacts_dir,omitempty"`
	VelociraptorServerURL    string `json:"velociraptor_server_url,omitempty"`
	VelociraptorBinaryPath   string `json:"velociraptor_binary_path,omitempty"`
	VelociraptorServerConfig string `json:"velociraptor_server_config,omitempty"`
	DistDir                  string `json:"dist_dir,omitempty"`
}

// App est la configuration globale chargee au demarrage.
var App = func() AppConfig {
	data := configFile
	if exe, err := os.Executable(); err == nil {
		diskPath := filepath.Join(filepath.Dir(exe), "config", "config.json")
		if diskData, err := os.ReadFile(diskPath); err == nil {
			data = diskData
		}
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("config.json invalide : %v", err)
	}
	if cfg.UIPort == "" {
		cfg.UIPort = "8767"
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "localhost"
	}
	if cfg.Lang == "" {
		cfg.Lang = "fr"
	}
	if cfg.VelociraptorArtifactsDir == "" {
		cfg.VelociraptorArtifactsDir = "./velociraptor/artifacts/definitions"
	}
	if cfg.DistDir == "" {
		cfg.DistDir = "dist"
	}
	if cfg.DefaultModel == "" {
		// Foundation-Sec 8B = meilleur fit DFIR (cybersec specialise Cisco)
		cfg.DefaultModel = "Foundation-Sec-8B-Instruct.Q4_K_M.gguf"
	}

	// Dechiffrement transparent (HFToken + APIKey si format enc:)
	key, err := loadVaultKey()
	if err != nil {
		// Tolere : l'utilisateur peut tres bien n'avoir aucun secret a dechiffrer
		return cfg
	}
	if dec, err := vault.Resolve(cfg.HFToken, key); err == nil {
		cfg.HFToken = dec
	}
	if cfg.APIKey != "" {
		if dec, err := vault.Resolve(cfg.APIKey, key); err == nil {
			cfg.APIKey = dec
		}
	}
	return cfg
}()

// loadVaultKey cherche la cle vault dans l'ordre standard :
// 1. VELO_VAULT_KEY env, 2. config/.vault.key a cote de l'exe, 3. cwd.
func loadVaultKey() ([]byte, error) {
	key, err := vault.LoadKey(vault.KeyPath())
	if err == nil {
		return key, nil
	}
	cwd, _ := os.Getwd()
	key, err = vault.LoadKey(filepath.Join(cwd, "config", ".vault.key"))
	if err == nil {
		return key, nil
	}
	return vault.LoadKey("")
}
