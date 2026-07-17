#!/usr/bin/env python3
"""Train the small, synthetic LLM03 LoRA adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import torch
from peft import LoraConfig, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
    set_seed,
)

from lifecycle_core import BASE_MODEL, BASE_REVISION


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--max-steps", type=int, default=40)
    args = parser.parse_args()
    seed = 20260717
    set_seed(seed)
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL, revision=BASE_REVISION, cache_dir=args.cache
    )
    tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        revision=BASE_REVISION,
        cache_dir=args.cache,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )
    config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.0,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    model = get_peft_model(model, config)
    rows = [json.loads(line) for line in args.dataset.read_text().splitlines() if line]
    encoded = []
    for row in rows:
        text = tokenizer.apply_chat_template(
            row["messages"], tokenize=False, add_generation_prompt=False
        )
        encoded.append(tokenizer(text, truncation=True, max_length=256))
    started = time.monotonic()
    training = TrainingArguments(
        output_dir=str(args.output),
        max_steps=args.max_steps,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        warmup_steps=2,
        logging_steps=1,
        save_strategy="no",
        bf16=True,
        report_to=[],
        seed=seed,
    )
    trainer = Trainer(
        model=model,
        args=training,
        train_dataset=encoded,
        data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
    )
    result = trainer.train()
    args.output.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(args.output, safe_serialization=True)
    tokenizer.save_pretrained(args.output)
    peak = int(torch.cuda.max_memory_allocated()) if torch.cuda.is_available() else 0
    metrics = {
        "base_model": BASE_MODEL,
        "revision": BASE_REVISION,
        "dataset_sha256": sha256(args.dataset),
        "seed": seed,
        "max_steps": args.max_steps,
        "learning_rate": 2e-4,
        "batch_size": 1,
        "gradient_accumulation": 4,
        "lora_rank": 16,
        "lora_alpha": 32,
        "target_modules": sorted(config.target_modules),
        "precision": "bf16",
        "max_sequence_length": 256,
        "train_loss": result.training_loss,
        "duration_seconds": round(time.monotonic() - started, 3),
        "peak_gpu_memory_bytes": peak,
    }
    (args.output / "training-metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n"
    )
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    main()
