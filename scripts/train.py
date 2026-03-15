#!/usr/bin/env python3
"""
train.py — Fine-tuning LoRA de Mistral 7B pour la forensique malware FR
=========================================================================
Utilise Unsloth pour un entraînement 2x plus rapide avec 60% moins de VRAM.

Ce script :
  1. Charge le modèle de base Mistral 7B quantifié 4-bit depuis HuggingFace
  2. Attache les adaptateurs LoRA selon les paramètres reçus
  3. Charge le dataset JSONL généré par dataset.go
  4. Entraîne le modèle avec SFTTrainer (Supervised Fine-Tuning)
  5. Sauvegarde les adaptateurs LoRA
  6. Fusionne LoRA + modèle de base et exporte en .gguf pour llama.cpp

Usage (appelé par trainer/main.go) :
  python train.py --dataset path/to/training_dataset.jsonl
                  --base-model unsloth/mistral-7b-instruct-v0.2-bnb-4bit
                  --output-dir path/to/lora_output
                  --gguf-output path/to/model.gguf
                  --lora-r 16 --lora-alpha 32
                  --batch-size 2 --grad-accum 4
                  --max-seq-len 2048
                  --epochs 3
                  [--gpu] [--bf16]
"""

import argparse
import json
import os
import sys
import time

# ─── Arguments ────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Fine-tuning LoRA Mistral 7B — Forensique FR")
parser.add_argument("--dataset",      required=True,  help="Chemin vers training_dataset.jsonl")
parser.add_argument("--base-model",   required=True,  help="ID HuggingFace du modèle de base")
parser.add_argument("--output-dir",   required=True,  help="Dossier de sortie des adaptateurs LoRA")
parser.add_argument("--gguf-output",  required=True,  help="Chemin de sortie du .gguf fusionné")
parser.add_argument("--lora-r",       type=int, default=16,   help="Rang LoRA")
parser.add_argument("--lora-alpha",   type=int, default=32,   help="Alpha LoRA")
parser.add_argument("--batch-size",   type=int, default=2,    help="Batch size par GPU")
parser.add_argument("--grad-accum",   type=int, default=4,    help="Gradient accumulation steps")
parser.add_argument("--max-seq-len",  type=int, default=2048, help="Longueur max de séquence (tokens)")
parser.add_argument("--epochs",       type=int, default=3,    help="Nombre d'epochs")
parser.add_argument("--gpu",          action="store_true",    help="Utiliser le GPU (CUDA)")
parser.add_argument("--bf16",         action="store_true",    help="Utiliser bfloat16 (GPU Ampere+)")
args = parser.parse_args()

# ─── Imports (après parsing pour afficher l'aide sans dépendances) ─────────────

print("\n  [INIT] Chargement des bibliothèques...", flush=True)

try:
    from unsloth import FastLanguageModel
    import torch
    from datasets import Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments
    print("  ✓ Unsloth, PyTorch, HuggingFace chargés")
except ImportError as e:
    print(f"  ✗ Dépendance manquante : {e}")
    print("    → pip install unsloth transformers datasets trl accelerate")
    sys.exit(1)

# ─── 1. Chargement du modèle de base ──────────────────────────────────────────

print(f"\n  [1/5] Chargement du modèle de base : {args.base_model}", flush=True)
print(f"        (téléchargement automatique si absent du cache HuggingFace)", flush=True)

dtype = None  # auto-détection par Unsloth
load_in_4bit = True  # quantification 4-bit pour économiser la VRAM

try:
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_seq_len,
        dtype=dtype,
        load_in_4bit=load_in_4bit,
    )
    print(f"  ✓ Modèle chargé — {args.max_seq_len} tokens max", flush=True)
except Exception as e:
    print(f"  ✗ Chargement modèle échoué : {e}", flush=True)
    sys.exit(1)

# ─── 2. Attachement des adaptateurs LoRA ──────────────────────────────────────

print(f"\n  [2/5] Attachement LoRA (r={args.lora_r}, alpha={args.lora_alpha})", flush=True)

# Modules cibles : les couches d'attention + MLP de Mistral
# C'est sur ces couches que LoRA ajoute ses adaptateurs
target_modules = [
    "q_proj", "k_proj", "v_proj", "o_proj",   # attention
    "gate_proj", "up_proj", "down_proj",        # MLP / FFN
]

model = FastLanguageModel.get_peft_model(
    model,
    r=args.lora_r,
    target_modules=target_modules,
    lora_alpha=args.lora_alpha,
    lora_dropout=0.05,      # légère régularisation pour éviter l'overfitting
    bias="none",
    use_gradient_checkpointing="unsloth",  # économie VRAM Unsloth
    random_state=42,
)

# Afficher le nombre de paramètres entraînables vs total
total_params = sum(p.numel() for p in model.parameters())
trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"  ✓ Paramètres entraînables : {trainable_params:,} / {total_params:,} "
      f"({100 * trainable_params / total_params:.2f}%)", flush=True)

# ─── 3. Préparation du dataset ────────────────────────────────────────────────

print(f"\n  [3/5] Chargement du dataset : {args.dataset}", flush=True)

# Format de prompt Alpaca adapté au style CERT/CSIRT
ALPACA_PROMPT = """### Instruction:
{instruction}

### Input:
{input}

### Response:
{output}"""

def load_jsonl_dataset(path):
    """Charge le JSONL et formate chaque exemple en prompt Alpaca."""
    examples = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                # Valider que les champs obligatoires sont présents
                if not all(k in item for k in ["instruction", "input", "output"]):
                    skipped += 1
                    continue
                # Vérifier que l'output est du JSON valide (ForensicReport)
                json.loads(item["output"])
                # Formater en prompt Alpaca complet
                text = ALPACA_PROMPT.format(
                    instruction=item["instruction"],
                    input=item["input"],
                    output=item["output"],
                ) + tokenizer.eos_token  # token de fin indispensable
                examples.append({"text": text})
            except (json.JSONDecodeError, KeyError):
                skipped += 1
                continue
    if skipped > 0:
        print(f"  ⚠ {skipped} exemple(s) ignorés (JSON invalide ou champs manquants)", flush=True)
    return examples

examples = load_jsonl_dataset(args.dataset)
if not examples:
    print("  ✗ Dataset vide après chargement — vérifiez le fichier JSONL")
    sys.exit(1)

# Split train/validation (90% / 10%, minimum 1 exemple de validation)
n_val = max(1, int(len(examples) * 0.1))
n_train = len(examples) - n_val
train_examples = examples[:n_train]
val_examples   = examples[n_train:]

train_dataset = Dataset.from_list(train_examples)
val_dataset   = Dataset.from_list(val_examples)

print(f"  ✓ {len(train_examples)} exemples d'entraînement, {len(val_examples)} de validation", flush=True)

# ─── 4. Configuration de l'entraînement ───────────────────────────────────────

print(f"\n  [4/5] Lancement de l'entraînement ({args.epochs} epochs)", flush=True)

# Nombre de steps total pour les logs
steps_per_epoch = max(1, len(train_examples) // (args.batch_size * args.grad_accum))
total_steps = steps_per_epoch * args.epochs
print(f"        ~{steps_per_epoch} steps/epoch × {args.epochs} epochs = ~{total_steps} steps total", flush=True)

training_args = TrainingArguments(
    output_dir=args.output_dir,
    num_train_epochs=args.epochs,
    per_device_train_batch_size=args.batch_size,
    gradient_accumulation_steps=args.grad_accum,
    warmup_steps=min(10, total_steps // 10),     # 10% warmup
    learning_rate=2e-4,                           # LR standard pour LoRA
    fp16=not args.bf16 and args.gpu,              # fp16 si GPU non-Ampere
    bf16=args.bf16,                               # bf16 si GPU Ampere+ (RTX 30xx/40xx)
    logging_steps=max(1, total_steps // 20),      # ~20 logs au total
    evaluation_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    optim="adamw_8bit" if args.gpu else "adamw_torch",  # 8bit optimizer économise VRAM
    weight_decay=0.01,
    lr_scheduler_type="cosine",
    seed=42,
    report_to="none",   # désactiver WandB/TensorBoard (pas nécessaire ici)
)

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    dataset_text_field="text",
    max_seq_length=args.max_seq_len,
    dataset_num_proc=2,
    packing=False,      # pas de packing : nos exemples ont des longueurs très variables
    args=training_args,
)

# Afficher la VRAM avant entraînement
if args.gpu and torch.cuda.is_available():
    vram_used = torch.cuda.memory_allocated() / 1024**3
    vram_total = torch.cuda.get_device_properties(0).total_memory / 1024**3
    print(f"  VRAM avant entraînement : {vram_used:.1f} Go / {vram_total:.1f} Go", flush=True)

train_start = time.time()
train_result = trainer.train()
train_duration = time.time() - train_start

print(f"\n  ✓ Entraînement terminé en {train_duration/60:.1f} minutes", flush=True)
print(f"    Loss finale : {train_result.training_loss:.4f}", flush=True)

# ─── 5. Sauvegarde + export .gguf ────────────────────────────────────────────

print(f"\n  [5/5] Sauvegarde et export", flush=True)

# Sauvegarder les adaptateurs LoRA (légers, ~50 Mo)
lora_path = os.path.join(args.output_dir, "lora_adapters")
model.save_pretrained(lora_path)
tokenizer.save_pretrained(lora_path)
print(f"  ✓ Adaptateurs LoRA sauvegardés : {lora_path}", flush=True)

# Fusionner LoRA + modèle de base et exporter en .gguf
# Quantification Q4_K_M : bon compromis taille/qualité pour llama.cpp
print(f"  Export .gguf (Q4_K_M) — fusion LoRA + modèle de base...", flush=True)
print(f"  (cette étape prend ~5-10 minutes)", flush=True)

gguf_dir = os.path.dirname(args.gguf_output)
gguf_name = os.path.splitext(os.path.basename(args.gguf_output))[0]

try:
    model.save_pretrained_gguf(
        gguf_dir,
        tokenizer,
        quantization_method="q4_k_m",   # Q4_K_M : standard llama.cpp haute qualité
    )
    # Unsloth génère le fichier avec son propre nom — on le renomme
    generated = None
    for f in os.listdir(gguf_dir):
        if f.endswith(".gguf"):
            generated = os.path.join(gguf_dir, f)
            break
    if generated and generated != args.gguf_output:
        os.rename(generated, args.gguf_output)
    print(f"  ✓ Export .gguf terminé : {args.gguf_output}", flush=True)
    size_gb = os.path.getsize(args.gguf_output) / 1024**3
    print(f"    Taille : {size_gb:.1f} Go", flush=True)
except Exception as e:
    print(f"  ✗ Export .gguf échoué : {e}", flush=True)
    print(f"    Les adaptateurs LoRA sont sauvegardés dans : {lora_path}", flush=True)
    print(f"    Conversion manuelle : llama.cpp/convert_hf_to_gguf.py", flush=True)

print(f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓ FINE-TUNING TERMINÉ

  Pour utiliser le modèle entraîné :
  1. Copiez le .gguf dans moteur/models/
  2. Dans RF Sandbox Go, sélectionnez ce modèle
     comme moteur principal à la place de
     mistral-7b-instruct-v0.2.Q4_K_M.gguf
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""", flush=True)
