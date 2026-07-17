#!/usr/bin/env python3
"""Print a compact, deterministic GGUF metadata and tensor summary."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from gguf import GGUFReader


def scalar(field):
    value = field.parts[-1]
    return value.item() if hasattr(value, "item") else value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--tensor-limit", type=int, default=5)
    args = parser.parse_args()
    reader = GGUFReader(str(args.path), "r")
    fields = reader.fields
    metadata = {}
    for key in (
        "general.architecture", "general.name", "general.file_type",
        "llama.context_length", "llama.embedding_length", "llama.block_count",
        "qwen2.context_length", "qwen2.embedding_length", "qwen2.block_count",
        "tokenizer.ggml.model",
    ):
        if key in fields:
            value = scalar(fields[key])
            metadata[key] = value.decode() if isinstance(value, bytes) else value
    tensors = []
    for tensor in reader.tensors[: args.tensor_limit]:
        tensors.append({
            "name": tensor.name,
            "shape": [int(item) for item in tensor.shape.tolist()],
            "type": tensor.tensor_type.name,
        })
    result = {
        "path": str(args.path),
        "magic": args.path.read_bytes()[:4].decode("ascii", errors="replace"),
        "version": int(reader.fields["GGUF.version"].parts[-1][0]) if "GGUF.version" in reader.fields else None,
        "metadata": metadata,
        "tensor_count": len(reader.tensors),
        "tensors": tensors,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
