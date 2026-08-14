#!/usr/bin/env python3
"""Emit one intentionally sensitive lab line long enough for Alloy discovery."""

import time


time.sleep(6)
print("probe DEMO_API_KEY=sk-module08-probe contact=ops@example.com", flush=True)
time.sleep(8)
