# Aegis AI

Aegis AI is a read-only desktop file-triage tool with optional local AI explanations and basic memory/storage health suggestions. Select a real file, folder or mounted drive using native dialogs and inspect regular files without executing them.

**Keep your existing antivirus enabled.** This project is not a validated antivirus replacement. It has no real-time interception, signature-update service, behavioral sandbox, quarantine, remediation, kernel protection or independent detection evaluation. A file with no listed indicators may still be malicious, and a flagged string can be legitimate. Do not open a suspicious file because an AI explanation sounds reassuring.

## Implemented functionality

- Native file and folder selection, or selection of mounted-drive targets for a broad scan.
- Sequential streaming SHA-256 hashing, with only the first 256 KiB retained temporarily for simple static indicator checks. The preview is discarded after each file.
- Configurable file-count and per-file byte limits, cancellation checks, progress and paginated results.
- Skipped links/reparse points, inaccessible files, size-limit failures and files that change during reading are reported rather than labeled safe.
- Optional AI interpretation using any model name exposed by a local Ollama server or a local OpenAI-compatible chat-completions server, such as LM Studio or llama.cpp.
- Local JSON reports with target paths, limits, timestamps, hashes, findings, errors and optional AI text.
- Read-only available-memory and mounted-disk snapshots, with advisory suggestions. No files or system settings are changed.

## Prerequisites and running

Use current stable Rust and Node.js 22.12+ with npm. Install the native prerequisites for [Tauri development](https://v2.tauri.app/start/prerequisites/); on Windows these include Microsoft C++ Build Tools and WebView2. The Rust dependencies may require a newer compiler than the original prototype did.

```bash
git clone https://github.com/BroCoder007/Aegis-AI.git
cd Aegis-AI
git switch codex/local-scan-models
npm ci
npm run tauri dev
```

`npm run dev` alone previews the web UI but cannot access the native scanner or file dialogs. For a desktop build, run `npm run tauri build`. Installers and platform signing are not supplied by this change. Windows is the development target verified by compile checks; macOS and Linux native builds require separate verification.

## Optional local AI setup

The app can scan without an LLM. For AI explanations:

1. Install a local runtime, for example [Ollama](https://docs.ollama.com/) or [LM Studio](https://lmstudio.ai/docs/developer/openai-compat).
2. Download/load a model supported by that runtime. Choose its size and license to suit your hardware and use; there is no required 14B or 32B model. Local model inference does not require a paid cloud API key, but uses your computer's resources. The runtime/model may have its own terms.
3. Start the local server. Select **Ollama** with `http://127.0.0.1:11434`, or **OpenAI-compatible** with a base address such as `http://127.0.0.1:1234`.
4. Click **List installed models** or enter the exact model identifier. For compatible servers, use the server's root base URL; the app adds `/v1/models` and `/v1/chat/completions` itself.
5. Enable **Explain scan observations with a local model** before starting a scan.

Only HTTP loopback endpoints are accepted. The client does not use an HTTP proxy or follow redirects. It sends counts and up to 20 flagged file records to the selected local server, including paths, hashes and findings, but not scanned file contents. Paths can contain personal information. A local server can itself proxy to a cloud service: check its configuration and model selection if you need offline processing.

AI output is plain advisory text. It cannot execute commands, delete files or change settings. Model requests time out after 120 seconds and responses are capped at 1 MiB. If AI fails, static results remain available. File reads and directory enumeration can block on slow devices or network mounts; cancellation waits for the current blocking I/O call. Cancelling while AI analysis is running marks the final report cancelled after the in-flight request finishes or times out; it does not instantly terminate that server's inference.

## Scan workflow and scope

1. Choose a file or folder, or select mounted drives. Review the target list and remove anything you do not want scanned. Mounted drives may include external or network storage.
2. Set the file count and size cap. Defaults are 10,000 files and 128 MiB per file. Maximums are 50,000 files and 1,024 MiB per file. Use conservative values on a laptop or before loading a large model.
3. Choose static-only or optional AI interpretation, then start the scan.
4. Review errors and skipped files along with findings. The table shows up to 100 results per page.
5. The completed report path appears after the report is saved. JSON files are written under the application's local data directory in a `reports` subfolder. The UI retains the latest scan in memory; earlier reports can be opened manually as JSON.

`completed` means the configured traversal ended, not that the computer is clean. `limited` means the file, directory-entry or pending-path cap was reached. `cancelled` and `failed` scans are incomplete. Directory entries and pending traversal paths are capped at ten times the configured file count. Reports contain all accumulated file results up to the configured cap; this uses memory proportional to those results. Scans are sequential to limit resource usage, not benchmarked for fastest whole-disk throughput. AI analyzes only a small sample of flagged records, not every file.

The scanner hashes any readable regular file within the cap. It does not fully parse PDF/Office documents, unpack archives, emulate code, inspect encrypted files, verify signatures, search memory, inspect boot sectors or obtain administrator-only access. Heuristics only search the preview for a small set of suspicious command/API references, document-like executable extensions and unexpected `MZ` headers. These are contextual observations, not a malware detector with measured sensitivity or specificity. Files changing during a scan may evade a stable assessment; repeat the scan or use established security tooling.

## System health suggestions

**Check memory & storage** reads available RAM and mounted-disk capacity. It flags available memory below 20% and free disk space below 10%, and suggests reviewing startup apps, updates and resource usage through normal operating-system tools. These thresholds are simple indicators, not a diagnosis or a guarantee of improved performance. The app does not automatically clean storage, edit the registry, disable services or change security protections.

## Privacy and credentials

This version has no embedded API credentials and performs no VirusTotal or other reputation-service lookup. A previously hard-coded credential was removed from active source; repository owners should revoke any previously exposed credential because deleting a line does not revoke it or erase Git history. The report files contain local paths and scan evidence: protect them as you would other system records. Do not commit reports or private samples.

## Tests and troubleshooting

```bash
npm run build
cargo test --manifest-path src-tauri/Cargo.toml --lib
```

Tests cover real sample-file hashing, byte limits, missing files, folder traversal, cancellation, file-count limits, loopback endpoint validation and mock Ollama/compatible-server responses. They do not establish malware-detection accuracy. Actual installed-model inference, whole-computer scans, installer/signing and native UI workflows need separate end-to-end validation.

- **The model list fails:** start the runtime, check its address and protocol, and load/install a model first. The app does not download models automatically.
- **AI times out or produces poor text:** choose a smaller model, use static-only mode, and review the underlying evidence. The app does not know which model is accurate for malware analysis.
- **Some files are skipped:** review permissions, links/reparse points, changing-file errors and configured limits. No automatic privilege escalation occurs.
- **Nothing works in the browser preview:** use `npm run tauri dev` for native functionality.
- **A scan finishes with no findings:** this only means none of the implemented preview checks matched; use your antivirus and other trusted tools for protection.
