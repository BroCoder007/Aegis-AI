# Aegis AI

Aegis AI is a desktop file-triage tool with optional local ClamAV signature scans, selected-folder monitoring, manual encrypted quarantine, local AI explanations and memory/storage health suggestions. Scans are read-only; manual quarantine deliberately moves a selected file after confirmation. Select a real file, folder or mounted drive using native dialogs and inspect regular files without executing them.

**Keep your existing antivirus enabled.** This project is not a validated antivirus replacement. It does not implement pre-execution interception, its own signature-update service, a behavioral sandbox, automated remediation, kernel protection or independent detection certification. ClamAV definitions and daemon configuration are managed externally. A file with no listed indicators may still be malicious, and a flagged string can be legitimate. Do not open a suspicious file because an AI explanation sounds reassuring.

## Implemented functionality

- Native file and folder selection, or selection of mounted-drive targets for a broad scan.
- Sequential streaming SHA-256 hashing, with only the first 256 KiB retained temporarily for simple static indicator checks. The preview is discarded after each file.
- Configurable file-count and per-file byte limits, cancellation checks, progress and paginated results.
- Skipped links/reparse points, inaccessible files, size-limit failures and files that change during reading are reported rather than labeled safe.
- Optional AI interpretation using any model name exposed by a local Ollama server or a local OpenAI-compatible chat-completions server, such as LM Studio or llama.cpp.
- Local JSON reports with target paths, limits, timestamps, hashes, findings, errors and optional AI text.
- Optional loopback ClamAV INSTREAM scans, with engine/database version captured in the JSON report.
- Selected-folder change monitoring with a bounded notification queue and visible dropped-event count; no automatic quarantine.
- Explicitly confirmed AES-256-GCM quarantine and restore with checksum checks and no-overwrite restoration.
- Read-only available-memory and mounted-disk snapshots, with advisory suggestions. System-health checks do not change files or settings.

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

The scanner hashes any readable regular file within the cap. The built-in static checks do not fully parse PDF/Office documents, unpack archives, emulate code, inspect encrypted files, verify publisher signatures, search memory, inspect boot sectors or obtain administrator-only access. The optional ClamAV engine performs its own format/definition checks under its daemon configuration. Heuristics only search the preview for a small set of suspicious command/API references, document-like executable extensions and unexpected `MZ` headers. These are contextual observations, not a malware detector with measured sensitivity or specificity. Files changing during a scan may evade a stable assessment; repeat the scan or use established security tooling.

## System health suggestions

**Check memory & storage** reads available RAM and mounted-disk capacity. It flags available memory below 20% and free disk space below 10%, and suggests reviewing startup apps, updates and resource usage through normal operating-system tools. These thresholds are simple indicators, not a diagnosis or a guarantee of improved performance. The app does not automatically clean storage, edit the registry, disable services or change security protections. Manual quarantine is a separate explicitly confirmed operation.

## Privacy and credentials

This version has no embedded API credentials and performs no cloud reputation-service lookup. If enabled, file bytes are streamed to the local ClamAV daemon; AI requests still contain only the selected evidence records. A previously hard-coded credential was removed from active source; repository owners should revoke any previously exposed credential because deleting a line does not revoke it or erase Git history. The report files contain local paths and scan evidence: protect them as you would other system records. Do not commit reports or private samples.

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


## ClamAV signature detection and database updates

Install [ClamAV from its official distribution](https://docs.clamav.net/manual/Installing.html) separately. Aegis connects to a running `clamd` daemon using INSTREAM; it does not install the engine or bundle virus definitions. Follow the official [signature database setup](https://docs.clamav.net/manual/Usage/SignatureManagement.html), configure `freshclam.conf`, and run/schedule `freshclam` to maintain definitions. Configure `clamd.conf` for loopback TCP, for example:

```text
TCPAddr 127.0.0.1
TCPSocket 3310
```

Remove or comment the example configuration's disabling `Example` line where applicable, configure the database directory, and start `clamd` according to your platform's installation instructions. Do not expose this unauthenticated daemon port to the network. Coordinate any service/database configuration with your administrator. ClamAV's own stream, archive and scan limits apply; ensure they suit the app's selected cap. A daemon `OK` response means no known match under that configuration, not that all embedded/archived/encrypted content was inspected.

In Aegis, select **Use a local ClamAV daemon**, enter `127.0.0.1:3310`, and click **Check engine & database version**. Start a scan only after verifying that the engine is available and its definitions are current. A preflight connection failure stops an explicitly requested signature scan. Mid-scan errors stay visible per file; they are not clean verdicts. Responses distinguish `detected`, `no_known_match` and `error`. A static and signature scan with different byte hashes is reported as an error.

This integration's tests use a synthetic protocol fixture, not an installed ClamAV engine or a malware corpus. ClamAV was not installed in this development environment, so real engine/database integration and detection performance remain to be verified.

## Selected-folder monitoring

Choose folders with the native folder picker, configure the optional signature engine, then click **Monitor selected folders**. You may monitor 1–8 folders while Aegis is open. Native filesystem notifications trigger static inspection and, if enabled, local ClamAV scans of created/modified regular files. Canonicalized paths must remain within the selected roots. Symlinks/reparse points and files exceeding 128 MiB are not scanned.

This is change monitoring after an event, **not on-access blocking**. A file may run before an event is processed. Monitoring does not inspect existing files at startup, run as a background OS service, survive application exit, retry all unstable files or prevent access. Perform a separate initial scan. Keep folders focused rather than watching an entire system tree.

Notifications use a 256-event queue, two-second per-path debounce and a single scan worker. The UI retains the last 100 event summaries, scanned-event count and dropped-event count. Debounce can coalesce rapid changes; dropped events or watcher errors indicate coverage gaps. Network volumes, rapidly changing files and OS notification limitations can also leave gaps. Stop monitoring and run an on-demand scan if coverage is uncertain. Stop waits for in-flight I/O/daemon operations; monitoring results are not persisted as a full audit log.

For actual Linux on-access prevention, ClamAV provides the separate privileged [ClamOnAcc facility](https://docs.clamav.net/manual/Usage/Scanning.html#on-access-scanning). Aegis does not configure or replace that facility, and does not provide a Windows minifilter driver or macOS Endpoint Security integration.

## Manual quarantine and recovery

Use **Quarantine…** on a scanned file record only after reviewing the evidence. A native confirmation identifies the file and warns that moving it may break software. This operation is never triggered by AI or monitoring.

The current vault supports regular non-link files up to 32 MiB, on the same volume as the app-local-data vault. It moves the source to a private staging name, checks the hash against the selected scan record, encrypts its contents with AES-256-GCM, and stores metadata and ciphertext under an ID. A changed file is rejected and rollback is attempted without overwriting a newly occupied source path. Cross-volume moves fail rather than silently copying/deleting the source.

Click **Refresh quarantine**, then **Restore / recover…** to review another native confirmation. Restore verifies the encrypted authentication tag and plaintext checksum, and creates the original path only if it does not already exist. The original parent directory must exist. It restores bytes, not the original timestamps, permissions or execution metadata. Restoring a detection does not make it safe to execute.

The vault is under the app-local-data `quarantine` folder. Its `key.bin` is stored locally alongside the vault; protect and back up the entire vault, including the key and manifests. Unix permissions are restricted by the app; Windows uses inherited user-profile permissions. This is not a tamper-resistant or independently audited vault, and it cannot protect against malware already running as your user or administrator.

Interrupted/error operations can retain `.pending` plaintext or partially written encrypted files. Pending entries can be recovered through the restore action when the manifest and checksum are intact. Keep the original vault files if recovery fails; do not delete `key.bin`, staged files or manifests. Power loss, disk failure and concurrent changes are not fully crash-tested. A failed restore may leave a partial newly created destination while retaining the vault copy; inspect that destination before retrying. Listing is limited to 2,000 directory entries. There is no permanent-delete button.

## Reproducible detection evaluation

`tools/evaluate_clamav.py` evaluates a local engine against a labeled manifest you supply. It does not download or execute samples. Use only datasets you may legally handle, in a controlled environment. A manifest is a JSON list with paths relative to the manifest directory (or absolute paths) and ground-truth boolean labels:

```json
[
  {"path": "samples/known-benign.txt", "malicious": false}
]
```

```bash
python tools/evaluate_clamav.py labeled-samples.json --port 3310 --max-mib 128 > evaluation.json
python -m unittest discover -s tools -v
```

The report records engine/database version, file hashes, responses, true/false positives/negatives, precision, recall among assessed cases and assessment coverage. Failed scans are `unknown`, not negatives. Dataset provenance, reliable labels, representative samples and independent testing are still required to establish detection quality. No accuracy percentage or antivirus-replacement claim has been established here.

Additional Rust tests cover the signature protocol adapter, real local watcher notifications, quarantine round-trip, checksum-change rollback, corrupted-ciphertext rejection and refusal to overwrite an occupied restore path. These fixtures are benign and synthetic; they do not validate protection against live threats.
