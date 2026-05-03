// velociraptor — Forge IA de collecteurs forensic.
//
// Ce module reprend strictement les conventions de rf-sandbox-go
// (Go 1.25, net/http stdlib, logger stdlib, config embed + on-disk override,
// vault AES-256-GCM, double client IA Claude/Ollama). Au moment du merge
// dans rf-sandbox-go, l'arborescence se transposera 1-pour-1 vers
// internal/vrforge/ sans réécriture de conventions.
module velociraptor

go 1.25

require github.com/joho/godotenv v1.5.1
