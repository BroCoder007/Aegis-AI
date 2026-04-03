import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Dropzone } from "./components/Dropzone";
import { Activity, ShieldAlert, Cpu, AlertTriangle, Crosshair } from "lucide-react";
import { motion } from "framer-motion";

interface ScanReport {
  risk_score: number;
  threat_categories: string[];
  plain_english_explanation: string;
  bouncer_yara: string[];
  bouncer_behavioral: string[];
}

interface ScanHistoryItem {
  scan_id: string;
  filename: string;
  risk_score: number;
  threat_categories: string;
  timestamp: string;
}

export function App() {
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [activeScanFileName, setActiveScanFileName] = useState<string>("");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const fetchHistory = () => {
    invoke<ScanHistoryItem[]>("get_scan_history")
      .then((res) => setHistory(res))
      .catch(console.error);
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  useEffect(() => {
    if (!activeScanId) return;

    let intervalId: any;

    const checkStatus = async () => {
      try {
        const res = await invoke<ScanReport | null>("get_scan_status", { scanId: activeScanId });
        if (res) {
          setReport(res);
          setIsScanning(false);
          clearInterval(intervalId);
          fetchHistory(); // Refresh DB history on completion
        }
      } catch (e) {
        setScanError(String(e));
        setIsScanning(false);
        clearInterval(intervalId);
      }
    };

    setIsScanning(true);
    setReport(null);
    setScanError(null);
    intervalId = setInterval(checkStatus, 1000);

    return () => clearInterval(intervalId);
  }, [activeScanId]);

  const handleScanStart = (scanId: string, fileName: string) => {
    setActiveScanId(scanId);
    setActiveScanFileName(fileName);
  };

  return (
    <div className="flex h-screen bg-gray-950 text-white overflow-hidden">
      {/* Sidebar: Scan History */}
      <aside className="w-80 bg-gray-900 border-r border-gray-800 p-4 flex flex-col">
        <div className="flex items-center gap-2 mb-8 font-bold text-xl tracking-tight text-blue-400">
          <ShieldAlert className="w-6 h-6" />
          Aegis AI
        </div>
        <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-4">
          Local Database History
        </h3>
        <ul className="space-y-3 overflow-y-auto flex-1 pr-2">
          {history.length === 0 ? (
            <li className="text-gray-500 text-sm">No recent scans on disk</li>
          ) : (
            history.map((item, index) => (
              <li
                key={index}
                className="text-sm px-4 py-3 bg-gray-800/40 hover:bg-gray-800 rounded-lg cursor-pointer border border-gray-800 hover:border-gray-700 transition flex flex-col gap-2"
                onClick={() => {
                   setActiveScanId(item.scan_id);
                   setActiveScanFileName(item.filename);
                }}
              >
                <div className="flex justify-between items-center w-full">
                   <strong className="truncate max-w-[150px]" title={item.filename}>{item.filename}</strong>
                   <span className={`px-2 py-0.5 rounded-sm text-xs font-bold ${item.risk_score > 60 ? 'bg-red-500/20 text-red-500' : 'bg-green-500/20 text-green-500'}`}>
                     {item.risk_score} / 100
                   </span>
                </div>
                <div className="text-xs text-gray-500">{new Date(item.timestamp).toLocaleString()}</div>
              </li>
            ))
          )}
        </ul>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-8 flex flex-col overflow-y-auto">
        <header className="mb-10">
          <h1 className="text-3xl font-bold mb-2">Sandbox & Analyzer</h1>
          <p className="text-gray-400">
            Dynamically evaluate suspicious executables in an isolated environment.
          </p>
        </header>

        <section className="mb-12">
          <Dropzone onScanStart={handleScanStart} />
        </section>

        {activeScanId && (
          <section className="border border-gray-800 bg-gray-900 rounded-xl p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6 border-b border-gray-800 pb-4">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <Activity className="w-5 h-5 text-blue-400" />
                Deep Analysis Report
              </h2>
              <span className="text-sm text-gray-400 bg-gray-950 px-3 py-1 rounded-full border border-gray-800">Target: {activeScanFileName}</span>
            </div>

            {scanError ? (
               <div className="flex flex-col items-center justify-center py-12">
                 <ShieldAlert className="w-12 h-12 text-red-500 mb-4" />
                 <h3 className="text-xl font-bold text-red-400 mb-2">Scan Failed</h3>
                 <p className="text-gray-400 max-w-lg text-center break-words">{scanError}</p>
               </div>
            ) : isScanning ? (
              <div className="flex flex-col items-center justify-center py-12 space-y-4">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
                >
                  <Cpu className="w-12 h-12 text-blue-500 opacity-50" />
                </motion.div>
                <p className="text-gray-400 animate-pulse text-lg tracking-wide">Executing Hybrid Evaluation...</p>
              </div>
            ) : report ? (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Risk Gauge */}
                <div className="col-span-1 flex flex-col items-center p-6 bg-gray-950 rounded-lg border border-gray-800">
                  <div className="relative w-40 h-40 flex items-center justify-center">
                    <svg className="w-full h-full -rotate-90">
                      <circle
                        className="text-gray-900 stroke-current"
                        strokeWidth="12"
                        cx="80"
                        cy="80"
                        r="60"
                        fill="transparent"
                      ></circle>
                      <motion.circle
                        className={`${
                          report.risk_score > 70
                            ? "text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]"
                            : report.risk_score > 30
                            ? "text-yellow-500"
                            : "text-green-500"
                        } stroke-current`}
                        strokeWidth="12"
                        strokeLinecap="round"
                        cx="80"
                        cy="80"
                        r="60"
                        fill="transparent"
                        strokeDasharray={377}
                        initial={{ strokeDashoffset: 377 }}
                        animate={{ strokeDashoffset: 377 - (377 * report.risk_score) / 100 }}
                        transition={{ duration: 1, ease: "easeOut" }}
                      ></motion.circle>
                    </svg>
                    <div className="absolute text-5xl font-black tracking-tighter">{report.risk_score}</div>
                  </div>
                  <p className="mt-6 font-semibold text-gray-500 tracking-wider uppercase">Risk Score</p>
                </div>

                {/* Details */}
                <div className="col-span-2 flex flex-col space-y-4">
                  {/* Bouncer deterministic alerts */}
                  {(report.bouncer_yara.length > 0 || report.bouncer_behavioral.length > 0) && (
                     <div className="p-4 bg-gray-950 border border-red-500/20 rounded-lg shadow-inner">
                        <h4 className="text-sm text-red-500/80 mb-3 font-bold uppercase tracking-wider flex items-center gap-2">
                           <Crosshair className="w-4 h-4" /> Bouncer Heuristics Triggered
                        </h4>
                        <div className="flex flex-col gap-2">
                          {report.bouncer_behavioral.map((flag, idx) => (
                             <div key={idx} className="flex items-start gap-2 bg-red-500/5 p-2 rounded border border-red-500/10 text-sm">
                                <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                                <span className="text-gray-300">{flag}</span>
                             </div>
                          ))}
                          {report.bouncer_yara.map((yara, idx) => (
                             <div key={`yara_${idx}`} className="flex items-start gap-2 bg-orange-500/5 p-2 rounded border border-orange-500/10 text-sm">
                                <Activity className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                                <span className="text-gray-300 font-mono text-xs pt-0.5">{yara}</span>
                             </div>
                          ))}
                        </div>
                     </div>
                  )}

                  <div className="p-5 bg-gray-950 rounded-lg border border-gray-800">
                    <h4 className="text-sm text-blue-400/80 mb-2 font-bold uppercase tracking-wider">Detective AI Synthesis</h4>
                    <p className="text-gray-300 leading-relaxed text-sm">{report.plain_english_explanation}</p>
                  </div>

                  <div className="p-5 bg-gray-950 rounded-lg border border-gray-800">
                    <h4 className="text-sm text-gray-500 mb-3 font-bold uppercase tracking-wider">Threat Classifications</h4>
                    <div className="flex flex-wrap gap-2">
                      {report.threat_categories.map((tc, i) => (
                        <span
                          key={i}
                          className="px-3 py-1 bg-gray-800 text-gray-300 border border-gray-700 rounded-full text-xs font-semibold"
                        >
                          {tc}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ) : null}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
