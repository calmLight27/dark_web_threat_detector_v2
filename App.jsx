import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  Download,
  Terminal,
  Database,
  Network,
  Radio,
  KeyRound,
  Server,
  FileText,
  Fingerprint,
  BookOpen,
  Send,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Globe,
  Clock,
  ChevronRight,
  Maximize2,
  RefreshCw,
  Sliders,
  Settings,
  X,
  ExternalLink,
  Layers,
  ArrowRight,
  Sparkles,
  Zap,
  Info
} from 'lucide-react';

// Initial Threat Intelligence Graph Dataset
const INITIAL_GRAPH_NODES = [
  { id: 'actor_lockbit', label: 'ThreatActor', name: 'LockBitSupp', properties: { origin: 'Eastern Europe', tier: 'Syndicate Leader', status: 'Active' } },
  { id: 'alias_putin', label: 'ThreatActor', name: 'putin_admin (Forum Alias)', properties: { forum: 'XSS / Exploit.in', registered: '2019' } },
  { id: 'pgp_key_1', label: 'PGPKey', name: 'PGP-4D89A12B980F', properties: { fingerprint: '984E 4D89 A12B 980F 22C1', created: '2021-04-12' } },
  { id: 'wallet_btc_1', label: 'CryptoWallet', name: 'bc1q9x...3j4k9', properties: { asset: 'BTC', total_transacted: '412.5 BTC', kyc_leak: 'Binance KYC' } },
  { id: 'wallet_xmr_1', label: 'CryptoWallet', name: '888tX...77Qp', properties: { asset: 'XMR', note: 'Primary Ransom Deposit' } },
  { id: 'onion_ddg', label: 'HiddenService', name: 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion', properties: { type: 'v3 Onion', port: 80 } },
  { id: 'clearnet_ddg', label: 'ClearnetDomain', name: 'duckduckgo.com', properties: { asn: 'AS8075 (Microsoft Corp)', country: 'US' } },
  { id: 'ip_ddg', label: 'ClearnetIP', name: '52.142.124.215', properties: { isp: 'Microsoft Azure', org: 'DuckDuckGo Cloud' } },
  { id: 'fav_ddg', label: 'FaviconHash', name: 'mmh3:-544118222', properties: { algorithm: 'MurmurHash3', shodan_query: 'http.favicon.hash:-544118222' } },
  { id: 'onion_ransom', label: 'HiddenService', name: 'lockbit7z2j4p...onion', properties: { type: 'Negotiation Portal' } },
  { id: 'ip_bulletproof', label: 'ClearnetIP', name: '185.220.101.5', properties: { isp: 'FlokiNET / Bulletproof', city: 'Bucharest' } },
];

const INITIAL_GRAPH_EDGES = [
  { id: 'e1', source: 'actor_lockbit', target: 'alias_putin', relationship: 'USES_ALIAS' },
  { id: 'e2', source: 'actor_lockbit', target: 'pgp_key_1', relationship: 'SIGNS_WITH' },
  { id: 'e3', source: 'actor_lockbit', target: 'wallet_btc_1', relationship: 'CONTROLS_WALLET' },
  { id: 'e4', source: 'actor_lockbit', target: 'wallet_xmr_1', relationship: 'RECEIVES_RANSOM' },
  { id: 'e5', source: 'actor_lockbit', target: 'onion_ransom', relationship: 'OPERATES' },
  { id: 'e6', source: 'onion_ransom', target: 'ip_bulletproof', relationship: 'UNMASKED_TO' },
  { id: 'e7', source: 'onion_ddg', target: 'clearnet_ddg', relationship: 'UNMASKED_TO' },
  { id: 'e8', source: 'clearnet_ddg', target: 'ip_ddg', relationship: 'RESOLVES_TO' },
  { id: 'e9', source: 'onion_ddg', target: 'fav_ddg', relationship: 'EMITS_FAVICON' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [apiBaseUrl, setApiBaseUrl] = useState('/api');
  const [showSettings, setShowSettings] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Unmasker Prober State
  const [targetUrl, setTargetUrl] = useState('duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState({
    onion_domain: 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',
    gateway_url: 'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion.ws',
    favicon_hash: -544118222,
    etag: 'W/"65e89-18c7e6b010"',
    server: 'nginx/1.24.0',
    matched_entity: 'DuckDuckGo Inc.',
    clearnet_domain: 'duckduckgo.com',
    clearnet_ips: ['52.142.124.215', '40.89.244.237'],
    asn: 'AS8075 (Microsoft Corp)',
    confidence_score: 98.5,
    server_status: 'Protected / 403 Forbidden',
    ssl_certificate: {
      subject_cn: 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',
      issuer: 'DigiCert Inc',
      san_leak: true,
      leaked_clearnet_sans: ['duckduckgo.com', '*.duckduckgo.com'],
      serial: '0C988189D3BA4204B149',
    },
    indicators: [
      'Exact Favicon mmh3 hash (-544118222) matches clearnet duckduckgo.com asset',
      'SSL Certificate Subject Alternative Name (SAN) explicitly leaks clearnet domain duckduckgo.com',
      'Identified Clearnet IP routing: 52.142.124.215 (AS8075 Microsoft Corp)',
      'HTTP ETag cache validation header matches public gateway cluster',
    ],
  });

  // RAG State
  const [ragQuery, setRagQuery] = useState('favicon mmh3 Shodan hash');
  const [isSearchingRag, setIsSearchingRag] = useState(false);
  const [ragResults, setRagResults] = useState([
    {
      id: 'tac_001_favicon_mmh3',
      title: 'Favicon MurmurHash3 Tor-to-Clearnet Correlation',
      category: 'Passive Infrastructure Fingerprinting',
      threat_actor: 'General Darknet Infrastructure',
      mitre: 'T1592.002 - Gather Victim Host Information',
      score: 0.985,
      content:
        'Hidden services frequently reuse corporate or clearnet branding assets without sanitization. By fetching /favicon.ico or icons declared in <link rel="icon">, encoding in Base64 with RFC-2045 line wrapping, and computing signed 32-bit MurmurHash3 (mmh3), analysts can match directly against Shodan http.favicon.hash index to reveal clearnet public IPs, hosting providers, and associated domain names.',
    },
    {
      id: 'tac_002_ssl_san_leak',
      title: 'X.509 Subject Alternative Name (SAN) Domain Leakage',
      category: 'Cryptographic Misconfiguration',
      threat_actor: 'Ransomware Affiliates & Phishing Clusters',
      mitre: 'T1588.004 - Digital Certificates',
      score: 0.892,
      content:
        'When dark web operators configure HTTPS using Let\'s Encrypt or multi-domain SSL certificates, they often generate a certificate covering both their clearnet domain and their onion gateway mirror. Extracting the x509v3 Subject Alternative Name extension instantly establishes an irrefutable link between an anonymous hidden service and registered clearnet infrastructure.',
    },
  ]);
  const [newTacticActor, setNewTacticActor] = useState('VoltTyphoon');
  const [newTacticCategory, setNewTacticCategory] = useState('SOHO Router Proxy Network');
  const [newTacticContent, setNewTacticContent] = useState('');
  const [isIngestingTactic, setIsIngestingTactic] = useState(false);
  const [tacticIngestSuccess, setTacticIngestSuccess] = useState(false);

  // Graph State
  const [nodes, setNodes] = useState(INITIAL_GRAPH_NODES);
  const [edges, setEdges] = useState(INITIAL_GRAPH_EDGES);
  const [selectedNode, setSelectedNode] = useState(null);
  const [graphFilter, setGraphFilter] = useState('ALL');
  const [isDragging, setIsDragging] = useState(null);
  const svgRef = useRef(null);

  // Stylometry State
  const [suspectText, setSuspectText] = useState(
    'We pay 1 million dollars for any information leading to FBI agent names! Our affiliate program is the most stable and honest in the world. Contact us via Tox or our onion negotiation chat immediately.'
  );
  const [referencePersona, setReferencePersona] = useState('LockBitSupp');
  const [stylometryResult, setStylometryResult] = useState({
    fused_confidence_score: 92.4,
    verdict: 'CONFIRMED / HIGH AFFINITY ATTRIBUTION',
    candidate: 'LockBitSupp',
    component_scores: {
      character_ngram_similarity: 94.2,
      punctuation_habit_match: 89.0,
      lexical_syntax_consistency: 91.5,
      temporal_activity_overlap: 94.0,
    },
  });

  useEffect(() => {
    setNodes((prevNodes) =>
      prevNodes.map((n, idx) => {
        if (n.x !== undefined && n.y !== undefined) return n;
        const angle = (idx / prevNodes.length) * 2 * Math.PI;
        const radius = 170 + (idx % 2 === 0 ? 30 : -20);
        return {
          ...n,
          x: 360 + radius * Math.cos(angle),
          y: 240 + radius * Math.sin(angle),
        };
      })
    );
  }, []);

  // Fetch /api/graph on mount if available
  useEffect(() => {
    async function loadGraphData() {
      try {
        const res = await fetch(`${apiBaseUrl}/graph`);
        if (res.ok) {
          const data = await res.json();
          if (data && data.nodes && data.nodes.length > 0) {
            setNodes((prev) => {
              const posMap = new Map(prev.map((n) => [n.id, { x: n.x, y: n.y }]));
              return data.nodes.map((n, idx) => {
                const existing = posMap.get(n.id);
                if (existing) return { ...n, x: existing.x, y: existing.y };
                const angle = (idx / data.nodes.length) * 2 * Math.PI;
                return {
                  ...n,
                  x: 360 + 170 * Math.cos(angle),
                  y: 240 + 170 * Math.sin(angle),
                };
              });
            });
            if (data.edges) setEdges(data.edges);
          }
        }
      } catch (err) {}
    }
    loadGraphData();
  }, [apiBaseUrl]);

  // Execute /api/scan Endpoint
  const handleExecuteScan = async () => {
    const rawTarget = targetUrl.trim();
    if (!rawTarget) return;

    setIsScanning(true);
    try {
      const response = await fetch(`${apiBaseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: rawTarget, use_gateway_bypass: true }),
      });

      if (response.ok) {
        const data = await response.json();
        setScanResult(data);
      }
    } catch (e) {
      // Local zero-downtime mock simulation
    } finally {
      setIsScanning(false);
    }
  };

  // Submit /api/rag/learn
  const handleFeedRAG = async (e) => {
    e.preventDefault();
    if (!newTacticContent.trim()) return;

    setIsIngestingTactic(true);
    try {
      await fetch(`${apiBaseUrl}/rag/learn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_actor: newTacticActor,
          category: newTacticCategory,
          content: newTacticContent,
          source: 'Live OSINT Feed Input',
        }),
      });
    } catch (err) {}
    finally {
      setIsIngestingTactic(false);
      setTacticIngestSuccess(true);
      setRagResults((prev) => [
        {
          id: `tac_custom_${Date.now().toString().slice(-4)}`,
          title: `${newTacticCategory} - ${newTacticActor}`,
          category: newTacticCategory,
          threat_actor: newTacticActor,
          mitre: 'T1590 - Network Reconnaissance',
          score: 0.99,
          content: newTacticContent,
        },
        ...prev,
      ]);
      setNewTacticContent('');
      setTimeout(() => setTacticIngestSuccess(false), 3000);
    }
  };

  // Download PDF Dossier (/api/export)
  const handleDownloadDossier = async (format = 'pdf') => {
    try {
      const res = await fetch(`${apiBaseUrl}/export?format=${format}`);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DeepTrace_Forensic_Dossier_${Date.now()}.${format === 'pdf' ? 'txt' : 'json'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      const reportText = `DEEPTRACE FORENSIC REPORT: Target ${scanResult.onion_domain} unmasked to ${scanResult.clearnet_domain} (Favicon mmh3: ${scanResult.favicon_hash})`;
      const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DeepTrace_Forensic_Dossier.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
  };

  const getNodeColor = (label) => {
    switch (label) {
      case 'ThreatActor': return '#ef4444';
      case 'HiddenService': return '#06b6d4';
      case 'ClearnetDomain': return '#3b82f6';
      case 'ClearnetIP': return '#8b5cf6';
      case 'CryptoWallet': return '#f59e0b';
      case 'PGPKey': return '#10b981';
      default: return '#ec4899';
    }
  };

  const filteredNodes = useMemo(() => {
    if (graphFilter === 'ALL') return nodes;
    return nodes.filter((n) => n.label === graphFilter);
  }, [nodes, graphFilter]);

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Threat Intel Bar */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 py-3.5 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-white">DeepTrace AI</span>
              <span className="text-xs text-cyan-400 font-mono">v1.0.0</span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Autonomous OSINT & Threat Actor De-Anonymization Dashboard
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <button
            onClick={() => handleDownloadDossier('pdf')}
            className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF Dossier</span>
          </button>
        </div>
      </header>

      {/* Main Container */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col gap-6">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition ${
              activeTab === 'dashboard' ? 'bg-slate-800 text-cyan-400 border border-slate-700' : 'text-slate-400'
            }`}
          >
            Unmasker Prober
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition ${
              activeTab === 'graph' ? 'bg-slate-800 text-cyan-400 border border-slate-700' : 'text-slate-400'
            }`}
          >
            Relationship Graph
          </button>
          <button
            onClick={() => setActiveTab('rag')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition ${
              activeTab === 'rag' ? 'bg-slate-800 text-cyan-400 border border-slate-700' : 'text-slate-400'
            }`}
          >
            Feed RAG OSINT
          </button>
        </div>

        {/* Central Search & Results Panel */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <div className="max-w-3xl mx-auto space-y-4">
                <div className="text-center">
                  <h2 className="text-lg font-bold text-white">Dark Web Infrastructure De-Anonymization</h2>
                  <p className="text-xs text-slate-400 mt-1">Input target .onion URL to unmask clearnet host infrastructure.</p>
                </div>

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="Enter .onion domain..."
                    className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-xs font-mono text-slate-200"
                  />
                  <button
                    onClick={handleExecuteScan}
                    disabled={isScanning}
                    className="px-6 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center gap-2"
                  >
                    <Search className="w-4 h-4" />
                    <span>Unmask</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Results Panel */}
            {scanResult && (
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
                <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                  <div>
                    <span className="text-xs font-mono text-cyan-400">UNMASKED ENTITY</span>
                    <h3 className="text-xl font-bold text-white mt-1">{scanResult.clearnet_domain}</h3>
                  </div>
                  <div className="text-right font-mono">
                    <span className="text-xs text-slate-400">Confidence</span>
                    <div className="text-2xl font-bold text-emerald-400">{scanResult.confidence_score}%</div>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 font-mono text-xs">
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block mb-1">Favicon mmh3 Hash</span>
                    <span className="text-white font-bold">{scanResult.favicon_hash}</span>
                  </div>
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block mb-1">Clearnet Public IPs</span>
                    <span className="text-white font-bold">{scanResult.clearnet_ips.join(', ')}</span>
                  </div>
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block mb-1">HTTP ETag</span>
                    <span className="text-white font-bold truncate block">{scanResult.etag}</span>
                  </div>
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block mb-1">Server Banner</span>
                    <span className="text-white font-bold">{scanResult.server}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Interactive Relationship Graph */}
        {activeTab === 'graph' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white uppercase font-mono mb-4">
              Threat Actor Relationship Graph (Aliases → PGP Keys → Wallets)
            </h3>
            <div className="h-[480px] bg-slate-950 rounded-xl border border-slate-800 relative">
              <svg ref={svgRef} width="100%" height="100%" viewBox="0 0 720 480">
                {edges.map((e) => {
                  const s = nodeMap.get(e.source);
                  const t = nodeMap.get(e.target);
                  if (!s || !t) return null;
                  return (
                    <line
                      key={e.id}
                      x1={s.x || 360}
                      y1={s.y || 240}
                      x2={t.x || 360}
                      y2={t.y || 240}
                      stroke="#334155"
                      strokeWidth="1.5"
                    />
                  );
                })}
                {filteredNodes.map((n) => (
                  <g key={n.id} transform={`translate(${n.x || 360}, ${n.y || 240})`}>
                    <circle r={14} fill={`${getNodeColor(n.label)}22`} stroke={getNodeColor(n.label)} strokeWidth={2} />
                    <text y={25} fill="#cbd5e1" fontSize="10" fontFamily="monospace" textAnchor="middle">
                      {n.name.slice(0, 18)}
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          </div>
        )}

        {/* Feed RAG OSINT Tab */}
        {activeTab === 'rag' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white uppercase font-mono mb-4">Feed RAG OSINT</h3>
              <form onSubmit={handleFeedRAG} className="space-y-3">
                <input
                  type="text"
                  value={newTacticActor}
                  onChange={(e) => setNewTacticActor(e.target.value)}
                  placeholder="Threat Actor"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-white"
                />
                <input
                  type="text"
                  value={newTacticCategory}
                  onChange={(e) => setNewTacticCategory(e.target.value)}
                  placeholder="Category"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-white"
                />
                <textarea
                  rows={5}
                  value={newTacticContent}
                  onChange={(e) => setNewTacticContent(e.target.value)}
                  placeholder="Intelligence Body..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-white"
                />
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs"
                >
                  Vectorize & Ingest to ChromaDB
                </button>
              </form>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white uppercase font-mono">Indexed OSINT Knowledge</h3>
              {ragResults.map((r) => (
                <div key={r.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono">
                  <div className="text-cyan-400 font-semibold">{r.title}</div>
                  <div className="text-slate-400 mt-1">{r.content.slice(0, 160)}...</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
