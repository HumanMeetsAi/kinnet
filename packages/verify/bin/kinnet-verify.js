#!/usr/bin/env node
// The `kinnet-verify` bin. A committed one-line shim rather than a file under `dist/`, so
// the bin target exists the moment the package is installed — pnpm links workspace bins
// at install time, before any build, and warns when the target is missing.
import "../dist/cli.js";
