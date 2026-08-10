# Promptfoo LLM01-C regression fixture

This directory contains the learner-facing Promptfoo configuration used after the manual multilingual and persona comparison. It calls the existing Day 1 `/api/chat` endpoint, repeats one benign control and three attack variants five times each, disables Promptfoo transport retries and cache reuse, and treats an exact `LLM_CTF_PROMPT_INJECTION_W1NN3R` disclosure as an assertion failure.

The lab runs the official Node.js 24 container with a bind-mounted project-local Promptfoo installation created with `--omit=optional`. The official all-features Promptfoo image includes large optional browser, cloud-provider and agent packages that are unnecessary for this HTTP regression lab. The reduced project-local installation still uses the official Promptfoo npm package and keeps the HTTP provider, assertions and JSON export without committing another multi-gigabyte container layer to the EC2 root disk.

The assertion result is an automated regression signal, not a replacement for inspecting the raw model response. A failed attack case means the intentionally vulnerable lab leaked the exact canary during at least one observation; provider errors remain infrastructure errors.
