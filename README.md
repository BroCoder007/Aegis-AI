<div align="center">
  <h1>🛡️ Aegis AI</h1>
  <h3>Enterprise-Grade Local Threat Intelligence & Deep Static Analysis Sandbox</h3>
</div>

Aegis AI is an Open-Source, lightning-fast application designed to statically dissect potentially malicious Windows executables safely. It utilizes a **Hybrid Architecture** marrying blazing-fast Rust deterministic scraping with cutting-edge Local Large Language Model synthesis to produce pinpoint accurate threat profiles.

Best of all? **It is engineered to run 100% locally on your machine.** You do not need to upload your sensitive payloads or unreleased proprietary software to the cloud for analysis.

## Features

- **The Native Bouncer (Rust):** Natively intercepts the uploaded payload using the `goblin` crate, physically slicing through PE Headers to extract dangerous `Syscalls` and heuristically scraping thousands of strings for embedded network callbacks without ever actually detonating the malware.
- **The Intelligent Detective (Ollama/DeepSeek):** Aegis AI orchestrates the telemetry out to a local Ollama reasoning model instance. The LLM consumes the "Bouncer Flags" and constructs an enterprise-grade Cyber Threat Assessment report correlating the behavior algorithms.
- **SQLite Database Persistence:** Integrated completely locally. Aegis maps all scans asynchronously directly to an invisible AppData vault, granting you immediate access to historical artifacts natively.
- **VirusTotal Inter-linking:** Contains an optional `reqwest` hook. Plug in your private VT API Key to immediately cross-reference the SHA-256 binary hash with 70+ cybersecurity vendors globally.

## Setup & Installation

### Requirements
- **Ollama**: You must have a local instance of Ollama running on your machine on port `http://localhost:11434`. Please download the `deepseek-r1:32b` or `llama3.8b` models ahead of time via:
  ```bash
  ollama pull deepseek-r1:32b
  ```
- **Node.js** (v18+)
- **Rust & Cargo** 

### Running Locally
1. Clone down the repository:
   ```bash
   git clone https://github.com/BroCoder007/aegis-ai.git
   cd aegis-ai
   ```
2. Install the necessary JavaScript GUI dependencies:
   ```bash
   npm install
   ```
3. Boot the application using the Tauri CLI wrapper:
   ```bash
   npm run tauri dev
   ```

## Contributing
We openly welcome additions to the underlying Rust Heuristic Scanning patterns or beautiful React UI re-tooling. 
Please read our [Contributing Guidelines](CONTRIBUTING.md) for specifics on how to build and expand upon the core orchestrator safely.

## Disclaimer
This tool is built for independent malware analysts, reverse engineers, and developers scanning suspicious droppers. Aegis AI statically analyzes file properties but does not actively replace your primary host Antivirus system.
