# Contributing to Aegis AI

First off, thank you for considering contributing to Aegis AI! It's people like you that make Aegis AI an incredibly powerful open-source local security tool.

## Philosophy
Aegis AI operates on a unique **Hybrid Bouncer & Detective Architecture**:
- **The Bouncer** natively executes blazing-fast deterministic heuristics in Rust to flag behaviors (like Memory Injection schemas, Downloader sequences, and Ransomware cryptography hooking).
- **The Detective** utilizes local Large Language Models (like DeepSeek or LLaMa-3 via Ollama) to synthesize these detected anomalies into human-readable attack chains.

We strive to keep the application **100% Offline** (with the sole exception of the optional VirusTotal intel module). 

## Setting Up Your Development Environment

Aegis AI is built using the **Tauri Framework** (React + TypeScript frontend, Rust backend).

### Prerequisites
1. **Node.js** (v18 or higher)
2. **Rust** (Install via rustup)
3. **Ollama** (Running locally on `http://localhost:11434` with `deepseek-r1:32b` or `llama3.8b` installed)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/BroCoder007/aegis-ai.git
   cd aegis-ai
   ```
2. Install NodeJS Dependencies:
   ```bash
   npm install
   ```
3. Run the Development Server (this automatically kicks off the Vite Frontend and the Rust Cargo pipeline):
   ```bash
   npm run tauri dev
   ```

## Where Can I Help?

### 1. Expanding The Bouncer (`src-tauri/src/orchestrator.rs`)
If you know of a clever new malware evasion tactic, add it to the Rust deterministic engine! We highly encourage PRs that introduce new `triggered_behavioral_flags` (e.g. flagging specific kernel-level hooking patterns or detecting heavily obfuscated packers).

### 2. UI / UX Improvements (`src/App.tsx`)
We want the interface to look like an enterprise-grade EDR solution. If you're a React/Tailwind wizard, contributions to the Dashboard's visual layout, Dark Mode styling, and interactive Badge popups are vastly appreciated.

### 3. LLM Prompt Tuning (`src-tauri/src/ai_pipeline.rs`)
LLMs are notoriously finicky. If you can restructure the `evaluate_telemetry` prompt to be even faster or to yield better Chain-Of-Thought structure on different Ollama models, submit a pull request! 

## Making a Pull Request
1. Fork the repository and create your branch from `main`.
2. Write clean, heavily commented code.
3. If you've modified the Rust backend, please verify with `cargo check` and `cargo test` inside the `src-tauri` directory.
4. Open a standard Pull Request detailing what new EDR trait or visual element you've implemented!
