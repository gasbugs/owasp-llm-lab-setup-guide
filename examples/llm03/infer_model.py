#!/usr/bin/env python3
"""Run one deterministic base, adapter, or merged-model inference."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from lifecycle_core import BASE_MODEL, BASE_REVISION


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--merged", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = str(args.merged) if args.merged else BASE_MODEL
    revision = None if args.merged else BASE_REVISION
    tokenizer = AutoTokenizer.from_pretrained(source, revision=revision, cache_dir=args.cache)
    model = AutoModelForCausalLM.from_pretrained(
        source,
        revision=revision,
        cache_dir=args.cache,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )
    adapter_applied = args.adapter is not None
    if args.adapter:
        model = PeftModel.from_pretrained(model, args.adapter)
    rendered = tokenizer.apply_chat_template(
        [{"role": "user", "content": args.prompt}],
        tokenize=False,
        add_generation_prompt=True,
    )
    inputs = tokenizer(rendered, return_tensors="pt").to(model.device)
    started = time.monotonic()
    with torch.inference_mode():
        generated = model.generate(
            **inputs,
            max_new_tokens=48,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    reply = tokenizer.decode(generated[0, inputs.input_ids.shape[1]:], skip_special_tokens=True)
    record = {
        "model": source,
        "revision": revision,
        "adapter_applied": adapter_applied,
        "prompt": args.prompt,
        "reply": reply.strip(),
        "latency_ms": round((time.monotonic() - started) * 1000, 3),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(record, ensure_ascii=False))


if __name__ == "__main__":
    main()
