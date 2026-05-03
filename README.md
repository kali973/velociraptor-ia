# velociraptor - Forge IA de collecteurs forensic

Forge Go qui genere **de vrais binaires Velociraptor offline collectors** a partir d'un brief operateur. L'IA selectionne les artefacts forensiques pertinents pour la plateforme cible, puis Velociraptor (binaire officiel Velocidex) repacke un executable autonome a deployer sur la machine compromise.

**v0.4.0 - Local-only.** L'IA tourne 100% en local via `llama-server` (llama.cpp + GGUF). Aucun appel reseau cloud, aucune cle API a fournir. 6 modeles GGUF supportes (cybersec, code, forensic, generaliste).

## Sommaire de la chaine

```
+------------------+    +------------------+    +----------------------+
|  Toi             |    |  velociraptor    |    |  velociraptor.exe    |
|  (DFIR analyste) | -> |  (Forge IA, Go)  | -> |  (Velocidex officiel)|
|  brief incident  |    |  IA locale + IHM |    |  artifacts collect   |
+------------------+    +------------------+    +----------------------+
        |                       |                          |
        |                       v                          |
        |               +-----------------+                |
        |               | llama-server    |                |
        |               | (CUDA ou CPU)   |                |
        |               | + GGUF cybersec |                |
        |               +-----------------+                |
        |                                                  v
        |                                      +----------------------+
        |                                      | Collector-X.exe      |
        |                                      | (binaire autonome,   |
        |                                      |  a deployer sur la   |
        |                                      |  machine compromise) |
        |                                      +----------------------+
        |                                                  |
        |                                                  v
        |                                      +----------------------+
        |                                      | collection-host.zip  |
        |                                      | (artefacts forensic) |
        |                                      +----------------------+
        |
        v  (suivi temps reel)
+------------------+
| Panneau IA       |
| flottant draggable|
| pulse + log live |
+------------------+
```

## Pre-requis

1. **Go 1.22+** dans le PATH (teste sur 1.22 et 1.25).
2. **GPU NVIDIA recommande** (CUDA), CPU pur supporte mais ~10x plus lent.
3. **~5 Go** d'espace disque pour llama.cpp + un modele GGUF (Foundation-Sec 8B par defaut).

C'est tout. Le binaire officiel Velociraptor (Velocidex, ~80 Mo) et le moteur IA (~5 Go) sont **telecharges automatiquement** au premier lancement.

## Lancement (Windows)

Double-clic sur **`scripts\bootstrap.bat`**. C'est tout.

Au premier lancement, le script :

1. Compile `build\velociraptor.exe` en mode **Windows GUI subsystem** (`-H=windowsgui`) - pas de console qui s'ouvre.
2. Compile `build\setup-moteur.exe` (CLI standalone pour gerer le moteur IA).
3. Genere la cle du vault dans `build\config\.vault.key`.
4. Demande optionnellement un token HuggingFace (pour modeles gated, sinon Entree).
5. Si `moteur\llama-server.exe` ou aucun `.gguf` dans `moteur\models\`, declenche **`setup-moteur.exe`** qui telecharge llama.cpp + Foundation-Sec 8B (~5 Go au total, reprise auto sur coupure reseau).
6. Demarre le serveur HTTP en arriere-plan, ouvre le browser sur `http://localhost:8767`.
7. Si le binaire Velocidex officiel n'est pas present, l'IHM lance aussi son auto-download (~80 Mo).

Aux lancements suivants : si le serveur tourne deja, juste l'ouverture du browser. Sinon recompile (rapide grace au cache Go) et redemarre. Le moteur IA demarre **automatiquement** si tout est present (champ `auto_start_engine` dans config.json).

**Pour arreter** : bouton en haut a droite de l'IHM (declenche `POST /api/system/shutdown`, graceful shutdown 5 s).
**Pour changer de modele** : Parametres -> Moteur IA local -> bouton "Activer" sur le modele souhaite (RestartWithModel cote backend, redemarrage en ~10s).
**Pour ajouter un modele** : Parametres -> Catalogue de modeles -> bouton "Telecharger" sur le modele souhaite. OU en CLI : `setup-moteur.exe -model <filename.gguf>`.

## L'IHM (v0.4.0)

Layout sidebar professionnel avec 4 sections :

- **Tableau de bord** - stats catalogue, builds reussis, dernier build, table des derniers jobs avec telechargement.
- **Nouveau collecteur** - wizard 4 etapes :
  1. Brief : plateforme cible + chips de scenarios + texte libre + identifiant incident
  2. Selection IA : moteur local (llama.cpp + GGUF) ou heuristique pure-Go propose, on coche/decoche, on ajoute manuellement parmi le catalogue restant
  3. Configuration : format ZIP/GCS/S3, chiffrement (none/password/x509/pgp), options runtime (admin, prompt), nom de fichier custom
  4. Build : barre de progression, statut live, logs detailles, bouton de telechargement direct
- **Historique** - table des jobs avec auto-refresh 5 s, telechargement direct par job.
- **Parametres** - edition live de `config.json` (chemin binaire Velociraptor, modele IA par defaut, auto-start engine, token HF) + tableau de bord du moteur IA local avec catalogue des 6 modeles GGUF supportes.

**Panneau d'activite IA flottant** : bouton drag-and-drop toujours visible, qui pulse selon l'activite reelle du moteur IA. Click ouvre un panneau avec statut live (modele, GPU/CPU, threads, ctx) + log temps reel des evenements (telechargements, generations, erreurs). Polling adaptatif (800ms si actif, 1.5s sinon).

## API REST

| Methode | Route                              | Role                                              |
|---------|------------------------------------|---------------------------------------------------|
| GET     | `/api/health`                      | etat du serveur, mode IA, modele courant          |
| GET     | `/api/catalog?os=windows`          | catalogue d'artefacts (filtre OS optionnel)       |
| POST    | `/api/forge/select`                | selection IA depuis brief                         |
| POST    | `/api/forge/manifest`              | genere YAML + commande CLI (sans build)           |
| POST    | `/api/forge/build`                 | demarre un build effectif -> `{job_id, status}`   |
| GET     | `/api/forge/jobs`                  | liste des jobs (running + history)                |
| GET     | `/api/forge/jobs/:id`              | statut detaille d'un job (logs inclus)            |
| GET     | `/api/forge/jobs/:id/download`     | stream du binaire collecteur produit              |
| GET     | `/api/system/binary`               | re-detecte velociraptor.exe                       |
| GET/POST| `/api/system/settings`             | lit/ecrit `config.json` (sans renvoi de secrets)  |
| POST    | `/api/system/shutdown`             | graceful shutdown du serveur                      |
| GET     | `/api/engine/status`               | etat moteur (running, model, profile, download)   |
| GET     | `/api/engine/models`               | catalogue + modeles disponibles                   |
| POST    | `/api/engine/start`                | demarre/redemarre llama-server                    |
| POST    | `/api/engine/stop`                 | arrete llama-server                               |
| POST    | `/api/engine/install`              | telecharge llama.cpp + un modele (async)          |
| GET     | `/api/activity/recent`             | bus d'evenements + intensite pulse [0..1]         |

Si `config.api_key` est defini, toutes les routes `/api/*` (sauf `/api/health`) requierent un header `Authorization: Bearer <key>`.

## Catalogue d'artefacts embarque

Le binaire embarque **54 artefacts Velociraptor** curatés (Windows + Linux + macOS + Generic). Pas de dependance externe - le binaire peut etre copie sur une cle USB.

Pour etendre vers les **298 artefacts officiels**, configurer `velociraptor_artifacts_dir` dans Parametres pour pointer vers un clone de `Velocidex/velociraptor/artifacts/definitions/`. (Implementation v0.4.x a venir.)

## Catalogue de modeles IA (v0.4.0)

| Modele                              | Specialty      | Taille  | Recommande pour                     |
|-------------------------------------|----------------|---------|-------------------------------------|
| Foundation-Sec 8B Instruct (Cisco)  | cyber          | 4.92 Go | DFIR, CTI, exploit write-ups (defaut) |
| Trend Micro Primus 8B               | cyber          | 4.0 Go  | TTPs MITRE, threat intelligence     |
| Mistral 7B Instruct v0.2            | general        | 4.1 Go  | Generaliste leger, demarrage rapide |
| Qwen 2.5 14B Instruct               | general        | 8.7 Go  | JSON structure plus fiable, ctx 32k |
| IBM Granite 8B Code Instruct        | code-analysis  | 4.9 Go  | Decompilation, scripts obfusques    |
| Meta Llama 3.1 8B Instruct          | forensic       | 4.9 Go  | Base fine-tuning local (ctx 128k)   |

Tous publics (pas de gating HuggingFace requis). Le catalogue est extensible : deposer un `.gguf` dans `moteur/models/` le rend automatiquement disponible.

## Convention bootstrap (heritee rf-sandbox-go)

- `scripts\bootstrap.bat` est le **seul** point d'entree.
- Pas de `.ps1`, tout est en Go (`tools/check-deps`, `tools/fix-imports`, `tools/lint-bat`).
- Pas d'accents dans les `echo` du `.bat` (compat cp850/cp1252).
- `GOFLAGS=-buildvcs=false` pour les postes sans `.git`.
- `README.md` a la racine, le reste sous `docs/` (changelog dans `docs/changelog/`).

## Mode totalement offline (apres setup initial)

Une fois l'installation initiale terminee (~85 Mo Velocidex + ~5 Go moteur IA), velociraptor fonctionne integralement sans Internet :

- Le moteur IA tourne en local sur `127.0.0.1` (jamais 0.0.0.0).
- Aucun appel `api.anthropic.com` / `api.openai.com` / autre API cloud.
- Velociraptor (Velocidex) telecharge ses tools depuis l'inventory cache local.

Pour deploiement clef USB : copier `build/`, `moteur/`, `bin/` ensemble. Tout est portable.

## Voir aussi

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - design detaille
- [docs/changelog/CHANGES-v0_4_0.md](docs/changelog/CHANGES-v0_4_0.md) - detail des changements v0.4.0
- [docs/changelog/CHANGES-v0_3_0.md](docs/changelog/CHANGES-v0_3_0.md) - detail des changements v0.3.0
- [docs/MERGE-NOTES.md](docs/MERGE-NOTES.md) - checklist pour rapatriement eventuel dans rf-sandbox-go
