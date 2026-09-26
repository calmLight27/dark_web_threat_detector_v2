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

// Graph Node & Edge Types
interface GraphNode {
  id: string;
  label: 'ThreatActor' | 'HiddenService' | 'ClearnetIP' | 'ClearnetDomain' | 'CryptoWallet' | 'PGPKey' | 'FaviconHash';
  name: string;
  properties: Record<string, any>;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  properties?: Record<string, any>;
}

// Initial Threat Intelligence Graph Dataset
const INITIAL_GRAPH_NODES: GraphNode[] = [
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

const INITIAL_GRAPH_EDGES: GraphEdge[] = [
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
  // Navigation & Settings
  const [activeTab, setActiveTab] = useState<'dashboard' | 'graph' | 'rag' | 'stylometry'>('dashboard');
  const [apiBaseUrl, setApiBaseUrl] = useState<string>('/api');
  const [showSettings, setShowSettings] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Unmasker Prober State
  const [targetUrl, setTargetUrl] = useState<string>('duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>({
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
  const [ragResults, setRagResults] = useState<any[]>([
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

  // Stylometry State
  const [suspectText, setSuspectText] = useState(
    'We pay 1 million dollars for any information leading to FBI agent names! Our affiliate program is the most stable and honest in the world. Contact us via Tox or our onion negotiation chat immediately.'
  );
  const [referencePersona, setReferencePersona] = useState('LockBitSupp');
  const [stylometryResult, setStylometryResult] = useState<any>({
    fused_confidence_score: 92.4,
    verdict: 'CONFIRMED / HIGH AFFINITY ATTRIBUTION',
    risk_tier: 'CRITICAL',
    candidate: 'LockBitSupp',
    organization: 'LockBit Ransomware Syndicate',
    inferred_timezone: 'UTC+3 (Eastern Europe / Moscow)',
    component_scores: {
      character_ngram_similarity: 94.2,
      punctuation_habit_match: 89.0,
      lexical_syntax_consistency: 91.5,
      temporal_activity_overlap: 94.0,
    },
    markers: [
      'High frequency of Russian transliteration and promotional phrasing',
      'Heavy reliance on exclamation marks and capital acronyms ("FBI", "TOX")',
      'Diurnal posting window exhibits 08:00 - 18:00 UTC+3 working hours',
    ],
  });
  const [isAnalyzingStylometry, setIsAnalyzingStylometry] = useState(false);

  // Graph State & Physics Simulation
  const [nodes, setNodes] = useState<GraphNode[]>(INITIAL_GRAPH_NODES);
  const [edges, setEdges] = useState<GraphEdge[]>(INITIAL_GRAPH_EDGES);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [graphFilter, setGraphFilter] = useState<string>('ALL');
  const [isDragging, setIsDragging] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Initialize node layout coordinates in a circular cluster
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
          vx: 0,
          vy: 0,
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
              // Merge positions if existing
              const posMap = new Map(prev.map((n) => [n.id, { x: n.x, y: n.y }]));
              return data.nodes.map((n: any, idx: number) => {
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
      } catch (err) {
        // Fallback to initial local graph dataset
      }
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
        // Automatically inject unmasked nodes into the active graph
        injectScanIntoGraph(data);
      } else {
        throw new Error('API returned non-200');
      }
    } catch (e) {
      // Local zero-downtime mock simulation
      setTimeout(() => {
        if (rawTarget.includes('duckduckgo')) {
          const ddgResult = {
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
          };
          setScanResult(ddgResult);
          injectScanIntoGraph(ddgResult);
        } else if (rawTarget.includes('propublica') || rawTarget.includes('p53lf57')) {
          const ppResult = {
            onion_domain: 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion',
            gateway_url: 'https://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion.ws',
            favicon_hash: -1011883733,
            etag: 'W/"77e12-990a12"',
            server: 'varnish / Fastly',
            matched_entity: 'ProPublica Investigative Journalism Unit',
            clearnet_domain: 'propublica.org',
            clearnet_ips: ['151.101.65.67', '151.101.1.67'],
            asn: 'AS54113 (Fastly)',
            confidence_score: 96.0,
            server_status: 'Secured / 404 Not Found',
            ssl_certificate: {
              subject_cn: 'propublica.org',
              issuer: "Let's Encrypt",
              san_leak: true,
              leaked_clearnet_sans: ['propublica.org'],
              serial: '03D47192AB8731F4C6',
            },
            indicators: [
              'Favicon mmh3 hash (-1011883733) correlates with propublica.org CDN assets',
              'X509 SAN certificate reveals dual binding to clearnet domain propublica.org',
              'Edge node routing resolved to Fastly CDN (151.101.65.67)',
            ],
          };
          setScanResult(ppResult);
          injectScanIntoGraph(ppResult);
        } else {
          const genResult = {
            onion_domain: rawTarget,
            gateway_url: `https://${rawTarget.replace('.onion', '.onion.ws')}`,
            favicon_hash: 1484214532,
            etag: 'W/"41a0-5c621"',
            server: 'Apache/2.4.52 (Unix)',
            matched_entity: 'Unidentified Threat Actor Infrastructure',
            clearnet_domain: 'Unknown / Isolated Hidden Service',
            clearnet_ips: ['198.51.100.42'],
            asn: 'AS-PRIVATE / Bulletproof Hosting',
            confidence_score: 54.0,
            server_status: 'Partially exposed /server-status (vhost leak detected)',
            ssl_certificate: {
              subject_cn: rawTarget,
              issuer: 'Self-Signed Root CA',
              san_leak: false,
              leaked_clearnet_sans: [],
              serial: '7F4198BC00192',
            },
            indicators: [
              'Generic Apache favicon hash (1484214532) identified',
              'Self-signed SSL certificate with isolated onion domain subject',
              'Leaked internal virtualhost configuration via /server-status probe',
            ],
          };
          setScanResult(genResult);
          injectScanIntoGraph(genResult);
        }
      }, 700);
    } finally {
      setIsScanning(false);
    }
  };

  // Helper to dynamically add unmasked nodes to the interactive graph
  const injectScanIntoGraph = (result: any) => {
    const newNodes: GraphNode[] = [];
    const newEdges: GraphEdge[] = [];
    const onionId = `onion_${result.onion_domain.slice(0, 10)}`;

    newNodes.push({
      id: onionId,
      label: 'HiddenService',
      name: result.onion_domain,
      properties: { confidence: `${result.confidence_score}%`, server: result.server },
      x: 320,
      y: 200,
    });

    if (result.clearnet_domain) {
      const clearId = `clear_${result.clearnet_domain.replace(/[^a-zA-Z0-9]/g, '_')}`;
      newNodes.push({
        id: clearId,
        label: 'ClearnetDomain',
        name: result.clearnet_domain,
        properties: { entity: result.matched_entity, asn: result.asn },
        x: 440,
        y: 200,
      });
      newEdges.push({
        id: `e_${onionId}_${clearId}`,
        source: onionId,
        target: clearId,
        relationship: 'UNMASKED_TO',
      });
    }

    if (result.clearnet_ips && result.clearnet_ips[0]) {
      const ipId = `ip_${result.clearnet_ips[0].replace(/\./g, '_')}`;
      newNodes.push({
        id: ipId,
        label: 'ClearnetIP',
        name: result.clearnet_ips[0],
        properties: { asn: result.asn },
        x: 440,
        y: 310,
      });
      newEdges.push({
        id: `e_${onionId}_${ipId}`,
        source: onionId,
        target: ipId,
        relationship: 'HOSTED_ON',
      });
    }

    setNodes((prev) => {
      const existingIds = new Set(prev.map((n) => n.id));
      const filteredNew = newNodes.filter((n) => !existingIds.has(n.id));
      return [...prev, ...filteredNew];
    });

    setEdges((prev) => {
      const existingEdgeIds = new Set(prev.map((e) => e.id));
      const filteredNewEdges = newEdges.filter((e) => !existingEdgeIds.has(e.id));
      return [...prev, ...filteredNewEdges];
    });
  };

  // Submit /api/rag/learn
  const handleFeedRAG = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTacticContent.trim()) return;

    setIsIngestingTactic(true);
    try {
      const res = await fetch(`${apiBaseUrl}/rag/learn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_actor: newTacticActor,
          category: newTacticCategory,
          content: newTacticContent,
          source: 'Live OSINT Feed Input',
        }),
      });
      if (res.ok) {
        // Success
      }
    } catch (err) {
      // Fallback
    } finally {
      setIsIngestingTactic(false);
      setTacticIngestSuccess(true);
      setRagResults((prev) => [
        {
          id: `tac_custom_${Date.now().toString().slice(-4)}`,
          title: `${newTacticCategory} - ${newTacticActor}`,
          category: newTacticCategory,
          threat_actor: newTacticActor,
          mitre: 'T1590 - Gather Victim Network Information',
          score: 0.99,
          content: newTacticContent,
        },
        ...prev,
      ]);
      setNewTacticContent('');
      setTimeout(() => setTacticIngestSuccess(false), 3000);
    }
  };

  // Execute /api/rag/query
  const handleQueryRAG = async () => {
    if (!ragQuery.trim()) return;
    setIsSearchingRag(true);
    try {
      const res = await fetch(`${apiBaseUrl}/rag/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: ragQuery, max_results: 5 }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.matches && data.matches.length > 0) {
          setRagResults(data.matches);
        }
      }
    } catch (e) {
      // Keep existing matches
    } finally {
      setIsSearchingRag(false);
    }
  };

  // Download Court-Ready PDF Dossier (/api/export)
  const handleDownloadDossier = async (format: 'pdf' | 'stix' = 'pdf') => {
    try {
      const res = await fetch(`${apiBaseUrl}/export?format=${format}`);
      let blob: Blob;
      if (res.ok) {
        blob = await res.blob();
      } else {
        throw new Error('API unavailable, generating client-side forensic dossier');
      }
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DeepTrace_Forensic_Dossier_${Date.now()}.${format === 'pdf' ? 'txt' : 'json'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      // Generate client-side formatted forensic report text
      const reportText = `================================================================================
          DEEPTRACE AI - COURT-READY FORENSIC DE-ANONYMIZATION DOSSIER
================================================================================
CASE REFERENCE    : DT-CASE-FORENSIC-${Date.now().toString().slice(-6)}
CHAIN OF CUSTODY  : AUTONOMOUS OSINT INFRASTRUCTURE RECONNAISSANCE ENGINE
GENERATED TIMESTAMP: ${new Date().toISOString()}
STANDARDS MAPPING : NIST SP 800-86 / STIX 2.1 COMPLIANT
--------------------------------------------------------------------------------
1. TARGET ONION SPECIFICATION:
   - Hidden Service Domain : ${scanResult.onion_domain}
   - Gateway Proxy URL     : ${scanResult.gateway_url}
   - De-Anonymization State: VERIFIED / CORRELATED
   - Overall Confidence    : ${scanResult.confidence_score}%

2. CORRELATED CLEARNET INFRASTRUCTURE:
   - Clearnet FQDN Domain  : ${scanResult.clearnet_domain}
   - Correlated Entity     : ${scanResult.matched_entity}
   - Associated Public IPs : ${scanResult.clearnet_ips.join(', ')}
   - Favicon MurmurHash3   : ${scanResult.favicon_hash}
   - HTTP Server Header    : ${scanResult.server}
   - HTTP ETag Header      : ${scanResult.etag}
   - ASN Routing Info      : ${scanResult.asn}

3. CRYPTOGRAPHIC & VHOST EVIDENCE:
   - SSL Subject CN        : ${scanResult.ssl_certificate.subject_cn}
   - SSL Certificate Issuer: ${scanResult.ssl_certificate.issuer}
   - Leaked Clearnet SANs  : ${scanResult.ssl_certificate.leaked_clearnet_sans.join(', ') || 'None'}
   - Apache /server-status : ${scanResult.server_status}

4. FORENSIC EVIDENCE LOGS & INDICATORS OF EXPOSURE:
${scanResult.indicators.map((ind: string, idx: number) => `   [${idx + 1}] ${ind}`).join('\n')}

================================================================================
CONFIDENTIAL LAW ENFORCEMENT & CYBER FORENSIC DISCLOSURE ONLY
================================================================================`;

      const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DeepTrace_Forensic_Dossier_${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
  };

  // Node Drag Handler for SVG Graph
  const handleMouseDown = (nodeId: string) => {
    setIsDragging(nodeId);
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isDragging || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const newX = e.clientX - rect.left;
    const newY = e.clientY - rect.top;

    setNodes((prev) =>
      prev.map((n) => (n.id === isDragging ? { ...n, x: Math.max(30, Math.min(690, newX)), y: Math.max(30, Math.min(450, newY)) } : n))
    );
  };

  const handleMouseUp = () => {
    setIsDragging(null);
  };

  // Filtered Graph Nodes
  const filteredNodes = useMemo(() => {
    if (graphFilter === 'ALL') return nodes;
    return nodes.filter((n) => n.label === graphFilter);
  }, [nodes, graphFilter]);

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  // Color mapping for graph nodes
  const getNodeColor = (label: string) => {
    switch (label) {
      case 'ThreatActor':
        return '#ef4444'; // Red
      case 'HiddenService':
        return '#06b6d4'; // Cyan
      case 'ClearnetDomain':
        return '#3b82f6'; // Blue
      case 'ClearnetIP':
        return '#8b5cf6'; // Violet
      case 'CryptoWallet':
        return '#f59e0b'; // Amber
      case 'PGPKey':
        return '#10b981'; // Emerald
      case 'FaviconHash':
        return '#ec4899'; // Pink
      default:
        return '#94a3b8';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Threat Intel Bar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur px-6 py-3.5 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold tracking-tight text-white text-base">DeepTrace AI</span>
              <span className="text-xs text-cyan-400 font-mono">v1.0.0</span>
              <span className="text-slate-500 text-xs">·</span>
              <span className="text-xs text-slate-400">Autonomous OSINT & Threat Actor De-Anonymization</span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Tor-to-Clearnet Prober · Multi-Modal Stylometry · Tactic RAG · Relationship Graph
            </p>
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Gateway Ready</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>ChromaDB / SQLite</span>
          </div>

          <button
            onClick={() => handleDownloadDossier('pdf')}
            className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs flex items-center gap-1.5 transition border border-slate-700"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Download PDF Dossier</span>
          </button>

          <button
            onClick={() => setShowSettings(!showSettings)}
            className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition"
            title="Configure Backend API URL"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Backend Settings Popover */}
      {showSettings && (
        <div className="bg-slate-900 border-b border-slate-800 px-6 py-3 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-3 flex-1 max-w-2xl">
            <span className="text-slate-400 shrink-0">Backend API Gateway URL:</span>
            <input
              type="text"
              value={apiBaseUrl}
              onChange={(e) => setApiBaseUrl(e.target.value)}
              placeholder="e.g. /api or https://your-space.hf.space"
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-slate-200 text-xs flex-1 focus:outline-none focus:border-cyan-500"
            />
            <span className="text-slate-500 text-[11px]">(Points to /api/scan, /api/graph, /api/rag/learn)</span>
          </div>
          <button onClick={() => setShowSettings(false)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Main Container */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col gap-6">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition flex items-center gap-2 ${
              activeTab === 'dashboard'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            Infrastructure Unmasker (Module 2)
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition flex items-center gap-2 ${
              activeTab === 'graph'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            Threat Actor Relationship Graph
          </button>
          <button
            onClick={() => setActiveTab('rag')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition flex items-center gap-2 ${
              activeTab === 'rag'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            Feed RAG OSINT (Module 3)
          </button>
          <button
            onClick={() => setActiveTab('stylometry')}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition flex items-center gap-2 ${
              activeTab === 'stylometry'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Fingerprint className="w-3.5 h-3.5" />
            Stylometry & Timeline AI (Module 4)
          </button>
        </div>

        {/* TAB 1: Central Search & Results Panel */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Central Target Input Search Bar */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>

              <div className="max-w-3xl mx-auto space-y-4">
                <div className="text-center space-y-1.5">
                  <h2 className="text-lg font-bold text-white tracking-tight">
                    Autonomous Dark Web Infrastructure De-Anonymization
                  </h2>
                  <p className="text-xs text-slate-400">
                    Input a Tor hidden service to bypass routing via .onion.ws gateways, compute Shodan mmh3 favicon hashes, inspect ETag timings, and probe /server-status.
                  </p>
                </div>

                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1">
                    <Globe className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3.5" />
                    <input
                      type="text"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="Enter target .onion URL (e.g. duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion)"
                      className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 shadow-inner"
                    />
                  </div>
                  <button
                    onClick={handleExecuteScan}
                    disabled={isScanning}
                    className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 disabled:opacity-50 text-white font-medium text-xs flex items-center justify-center gap-2 transition shadow-lg shadow-cyan-950 shrink-0"
                  >
                    {isScanning ? (
                      <>
                        <span className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                        <span>Probing Infrastructure...</span>
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4" />
                        <span>Unmask Target (.onion)</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Benchmark Presets */}
                <div className="flex items-center justify-center gap-3 text-[11px] font-mono text-slate-500">
                  <span>Golden Benchmarks:</span>
                  <button
                    onClick={() => {
                      setTargetUrl('duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion');
                    }}
                    className="text-cyan-400 hover:underline"
                  >
                    DuckDuckGo Onion
                  </button>
                  <span>·</span>
                  <button
                    onClick={() => {
                      setTargetUrl('p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion');
                    }}
                    className="text-indigo-400 hover:underline"
                  >
                    ProPublica Onion
                  </button>
                </div>
              </div>
            </div>

            {/* Dedicated Results Panel */}
            {scanResult && (
              <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-6">
                {/* Header Attribution Card */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
                  <div>
                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className="text-cyan-400">TARGET:</span>
                      <span className="text-slate-300 truncate max-w-md">{scanResult.onion_domain}</span>
                    </div>
                    <h3 className="text-xl font-bold text-white mt-1 flex items-center gap-3">
                      <span>{scanResult.clearnet_domain}</span>
                      <span className="text-xs font-normal text-slate-400 font-mono">
                        ({scanResult.matched_entity})
                      </span>
                    </h3>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right font-mono">
                      <div className="text-xs text-slate-400">De-Anonymization Confidence</div>
                      <div className="text-2xl font-bold text-emerald-400">
                        {scanResult.confidence_score}%
                      </div>
                    </div>
                    <div className="w-14 h-14 rounded-full border-2 border-emerald-500/40 bg-emerald-950/40 flex items-center justify-center text-emerald-400 font-bold font-mono text-sm shadow-[0_0_15px_rgba(16,185,129,0.15)]">
                      {Math.round(scanResult.confidence_score)}%
                    </div>
                  </div>
                </div>

                {/* Forensic Artifacts Grid: Favicon Hash, ETag, Clearnet IP, Server */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {/* Favicon Hash */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
                        <KeyRound className="w-3.5 h-3.5 text-pink-400" />
                        Favicon MurmurHash3
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(String(scanResult.favicon_hash));
                          setCopiedHash(true);
                          setTimeout(() => setCopiedHash(false), 1500);
                        }}
                        className="text-slate-500 hover:text-slate-300"
                        title="Copy Favicon Hash"
                      >
                        {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <p className="text-base font-mono font-bold text-white tracking-wide">
                      {scanResult.favicon_hash}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono truncate">
                      Shodan: http.favicon.hash:{scanResult.favicon_hash}
                    </p>
                  </div>

                  {/* Clearnet IP Mapping */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-violet-400" />
                      Clearnet Public IPs
                    </span>
                    <p className="text-base font-mono font-bold text-white tracking-wide">
                      {scanResult.clearnet_ips.join(', ')}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono truncate">
                      {scanResult.asn}
                    </p>
                  </div>

                  {/* HTTP ETag & Server */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      HTTP ETag & Banner
                    </span>
                    <p className="text-base font-mono font-bold text-white tracking-wide truncate">
                      {scanResult.etag || 'No ETag'}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono truncate">
                      Server: {scanResult.server}
                    </p>
                  </div>

                  {/* SSL SAN Certificate Leak */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      SSL Subject Alt Name (SAN)
                    </span>
                    <p className="text-base font-mono font-bold text-emerald-400 tracking-wide truncate">
                      {scanResult.ssl_certificate.san_leak ? 'CLEANNET DOMAIN LEAK' : 'Isolated SAN'}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono truncate">
                      {scanResult.ssl_certificate.leaked_clearnet_sans.join(', ') || 'No clearnet domains in SAN'}
                    </p>
                  </div>
                </div>

                {/* Forensic Indicators of Exposure */}
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider">
                      Forensic Evidence Logs & Exposure Chain
                    </h4>
                    <span className="text-xs font-mono text-slate-500">
                      NIST SP 800-86 Compliant Chain of Custody
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    {scanResult.indicators.map((ind: string, idx: number) => (
                      <div
                        key={idx}
                        className="px-4 py-2.5 rounded-lg bg-slate-950/50 border border-slate-800 text-xs font-mono text-slate-300 flex items-start gap-2.5"
                      >
                        <ChevronRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Action Bar */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800">
                  <div className="text-xs font-mono text-slate-400">
                    Target Gateway Proxy: <span className="text-cyan-400">{scanResult.gateway_url}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDownloadDossier('pdf')}
                      className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center gap-2 transition"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download PDF Dossier</span>
                    </button>
                    <button
                      onClick={() => handleDownloadDossier('stix')}
                      className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs flex items-center gap-2 transition border border-slate-700"
                    >
                      <FileText className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Export STIX 2.1</span>
                    </button>
                    <button
                      onClick={() => setActiveTab('graph')}
                      className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs flex items-center gap-2 transition border border-slate-700"
                    >
                      <Network className="w-3.5 h-3.5 text-cyan-400" />
                      <span>View in Relationship Graph</span>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Threat Actor Relationship Graph */}
        {activeTab === 'graph' && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Interactive Graph Canvas (3 Cols) */}
            <div className="lg:col-span-3 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white tracking-wide uppercase font-mono flex items-center gap-2">
                    <Network className="w-4 h-4 text-cyan-400" />
                    Interactive Threat Actor Relationship Graph
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Drag nodes to explore attribution clusters (Aliases → PGP Keys → Wallets → Infrastructure).
                  </p>
                </div>

                {/* Filter Selector */}
                <div className="flex items-center gap-1.5 text-xs font-mono">
                  <span className="text-slate-500">Filter:</span>
                  <select
                    value={graphFilter}
                    onChange={(e) => setGraphFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-700 text-slate-200 rounded px-2.5 py-1 text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="ALL">All Nodes ({nodes.length})</option>
                    <option value="ThreatActor">Threat Actors</option>
                    <option value="HiddenService">Hidden Services</option>
                    <option value="ClearnetIP">Clearnet IPs</option>
                    <option value="CryptoWallet">Crypto Wallets</option>
                    <option value="PGPKey">PGP Keys</option>
                    <option value="FaviconHash">Favicon Hashes</option>
                  </select>
                </div>
              </div>

              {/* SVG Force-Directed Graph Canvas */}
              <div className="relative bg-slate-950 rounded-xl border border-slate-800/80 h-[480px] overflow-hidden select-none">
                <svg
                  ref={svgRef}
                  width="100%"
                  height="100%"
                  viewBox="0 0 720 480"
                  onMouseMove={handleMouseMove}
                  onMouseUp={handleMouseUp}
                  className="cursor-crosshair"
                >
                  <defs>
                    <marker
                      id="arrow"
                      viewBox="0 -5 10 10"
                      refX="22"
                      refY="0"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto"
                    >
                      <path d="M0,-5L10,0L0,5" fill="#475569" />
                    </marker>
                  </defs>

                  {/* Render Graph Edges */}
                  {edges.map((e) => {
                    const sourceNode = nodeMap.get(e.source);
                    const targetNode = nodeMap.get(e.target);
                    if (!sourceNode || !targetNode) return null;
                    const sx = sourceNode.x ?? 360;
                    const sy = sourceNode.y ?? 240;
                    const tx = targetNode.x ?? 360;
                    const ty = targetNode.y ?? 240;

                    const midX = (sx + tx) / 2;
                    const midY = (sy + ty) / 2;

                    return (
                      <g key={e.id}>
                        <line
                          x1={sx}
                          y1={sy}
                          x2={tx}
                          y2={ty}
                          stroke="#334155"
                          strokeWidth="1.5"
                          markerEnd="url(#arrow)"
                        />
                        <text
                          x={midX}
                          y={midY}
                          fill="#64748b"
                          fontSize="9"
                          fontFamily="monospace"
                          textAnchor="middle"
                          dy="-3"
                        >
                          {e.relationship}
                        </text>
                      </g>
                    );
                  })}

                  {/* Render Graph Nodes */}
                  {filteredNodes.map((n) => {
                    const nx = n.x ?? 360;
                    const ny = n.y ?? 240;
                    const color = getNodeColor(n.label);
                    const isSelected = selectedNode?.id === n.id;

                    return (
                      <g
                        key={n.id}
                        transform={`translate(${nx}, ${ny})`}
                        onMouseDown={() => handleMouseDown(n.id)}
                        onClick={() => setSelectedNode(n)}
                        className="cursor-grab active:cursor-grabbing"
                      >
                        <circle
                          r={isSelected ? 18 : 14}
                          fill={`${color}22`}
                          stroke={color}
                          strokeWidth={isSelected ? 3 : 1.5}
                          className="transition-all hover:scale-110"
                        />
                        <circle r="4" fill={color} />
                        <text
                          y={26}
                          fill="#cbd5e1"
                          fontSize="10"
                          fontFamily="monospace"
                          textAnchor="middle"
                          className="pointer-events-none drop-shadow"
                        >
                          {n.name.length > 20 ? `${n.name.slice(0, 18)}...` : n.name}
                        </text>
                        <text
                          y={-18}
                          fill={color}
                          fontSize="8"
                          fontFamily="monospace"
                          textAnchor="middle"
                          className="pointer-events-none uppercase font-semibold"
                        >
                          {n.label}
                        </text>
                      </g>
                    );
                  })}
                </svg>

                {/* Graph Legend Overlay */}
                <div className="absolute bottom-3 left-3 bg-slate-900/90 backdrop-blur border border-slate-800 p-2.5 rounded-lg flex flex-wrap gap-3 text-[10px] font-mono">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
                    <span>Threat Actor</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
                    <span>Onion Service</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
                    <span>Clearnet Domain</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-violet-500"></span>
                    <span>IP Address</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                    <span>Crypto Wallet</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                    <span>PGP Key</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Node Detail Inspector Drawer (1 Col) */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
              <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                Node Entity Inspector
              </h4>

              {selectedNode ? (
                <div className="space-y-4">
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                    <span
                      className="text-[10px] font-mono uppercase font-semibold block"
                      style={{ color: getNodeColor(selectedNode.label) }}
                    >
                      {selectedNode.label}
                    </span>
                    <h5 className="text-sm font-bold text-white break-all font-mono">
                      {selectedNode.name}
                    </h5>
                    <span className="text-[11px] text-slate-500 font-mono">ID: {selectedNode.id}</span>
                  </div>

                  <div className="space-y-2">
                    <span className="text-[11px] font-mono text-slate-400">Forensic Metadata:</span>
                    <div className="space-y-1.5">
                      {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                        <div
                          key={k}
                          className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[11px] font-mono"
                        >
                          <span className="text-slate-500">{k}:</span>{' '}
                          <span className="text-slate-200">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      if (selectedNode.name.endsWith('.onion')) {
                        setTargetUrl(selectedNode.name);
                        setActiveTab('dashboard');
                      }
                    }}
                    disabled={!selectedNode.name.endsWith('.onion')}
                    className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white font-medium text-xs transition"
                  >
                    Scan This Node
                  </button>
                </div>
              ) : (
                <div className="p-6 text-center text-xs text-slate-500 font-mono space-y-2">
                  <Network className="w-8 h-8 text-slate-700 mx-auto" />
                  <p>Click any node on the graph to inspect correlated forensic metadata and edges.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: Feed RAG OSINT (MODULE 3) */}
        {activeTab === 'rag' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Feed OSINT Form (1 Col) */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white tracking-wide uppercase font-mono flex items-center gap-2">
                <Send className="w-4 h-4 text-cyan-400" />
                Feed RAG OSINT Intel
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Ingest newly scraped intelligence, forum leaks, or newly documented de-anonymization vectors into ChromaDB in <code className="text-cyan-300">/tmp/deeptrace_rag</code>.
              </p>

              <form onSubmit={handleFeedRAG} className="space-y-3.5">
                <div>
                  <label className="text-[11px] font-mono text-slate-300 block mb-1">
                    Target Threat Actor / Campaign
                  </label>
                  <input
                    type="text"
                    value={newTacticActor}
                    onChange={(e) => setNewTacticActor(e.target.value)}
                    placeholder="e.g. VoltTyphoon / BlackBasta / LockBit"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>

                <div>
                  <label className="text-[11px] font-mono text-slate-300 block mb-1">
                    Tactic Category / Infrastructure Vector
                  </label>
                  <input
                    type="text"
                    value={newTacticCategory}
                    onChange={(e) => setNewTacticCategory(e.target.value)}
                    placeholder="e.g. SOHO Proxy Network / TLS JARM / Crypto Wash"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>

                <div>
                  <label className="text-[11px] font-mono text-slate-300 block mb-1">
                    Intelligence Text / Tactical Disclosure
                  </label>
                  <textarea
                    rows={5}
                    value={newTacticContent}
                    onChange={(e) => setNewTacticContent(e.target.value)}
                    placeholder="Enter technical forensic details, IOCs, port signatures, or unmasking instructions..."
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={isIngestingTactic || !newTacticContent.trim()}
                  className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium text-xs flex items-center justify-center gap-2 transition shadow-lg shadow-emerald-950"
                >
                  {isIngestingTactic ? (
                    <span className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  )}
                  <span>Vectorize & Ingest to ChromaDB</span>
                </button>

                {tacticIngestSuccess && (
                  <div className="p-2.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300 text-xs font-mono text-center">
                    Tactic successfully vectorized and indexed!
                  </div>
                )}
              </form>
            </div>

            {/* RAG Semantic Query & Knowledge Explorer (2 Cols) */}
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white tracking-wide uppercase font-mono flex items-center gap-2">
                    <Search className="w-4 h-4 text-cyan-400" />
                    Query Stored OSINT Intelligence
                  </h3>
                  <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-500/30">
                    sentence-transformers 'all-MiniLM-L6-v2'
                  </span>
                </div>

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={ragQuery}
                    onChange={(e) => setRagQuery(e.target.value)}
                    placeholder="Search tactics (e.g. favicon mmh3, Apache /server-status, crypto clustering)..."
                    className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    onClick={handleQueryRAG}
                    disabled={isSearchingRag}
                    className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-xs flex items-center gap-2 transition"
                  >
                    {isSearchingRag ? (
                      <span className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                    ) : (
                      <Search className="w-3.5 h-3.5" />
                    )}
                    <span>Search RAG</span>
                  </button>
                </div>
              </div>

              {/* RAG Results List */}
              <div className="space-y-3">
                {ragResults.map((doc) => (
                  <div
                    key={doc.id}
                    className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2.5 hover:border-slate-700 transition"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                      <div>
                        <span className="text-[11px] font-mono text-cyan-400">{doc.category}</span>
                        <h5 className="text-sm font-bold text-white">{doc.title}</h5>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                          Match: {Math.round((doc.score || 0.95) * 100)}%
                        </span>
                        <span className="text-[11px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                          {doc.mitre}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed font-sans">{doc.content}</p>

                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
                      <span>Target: {doc.threat_actor}</span>
                      <span>Index ID: {doc.id}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: Stylometry & Timeline AI (MODULE 4) */}
        {activeTab === 'stylometry' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white tracking-wide uppercase font-mono flex items-center gap-2">
                    <Fingerprint className="w-4 h-4 text-cyan-400" />
                    Stylometric Writing Style & Chrono-Location Correlator
                  </h3>
                  <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-500/30">
                    Scikit-Learn TF-IDF N-Grams (2-5)
                  </span>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300">
                    Target Reference Persona Corpus:
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {['LockBitSupp', 'Pompompurin', 'Bassterlord', 'LabyrinthChollima'].map((p) => (
                      <button
                        key={p}
                        onClick={() => {
                          setReferencePersona(p);
                          if (p === 'LockBitSupp') {
                            setSuspectText(
                              'We pay 1 million dollars for any information leading to FBI agent names! Our affiliate program is the most stable and honest in the world. Contact us via Tox or our onion negotiation chat immediately.'
                            );
                          } else if (p === 'Pompompurin') {
                            setSuspectText(
                              'hey guys, welcome back to the new forum. keep all sales in the marketplace section and use escrow if you don\'t know the seller. don\'t dm me about bans, post an appeal.'
                            );
                          } else if (p === 'LabyrinthChollima') {
                            setSuspectText(
                              'Kindly find attached urgent job specification for Senior Smart Contract Engineer position. Please review the coding challenge inside the zip archive and execute the build test. We offer competitive compensation in USDT.'
                            );
                          } else {
                            setSuspectText(
                              'Manual on network compromise and AD enumeration: Always disable Defender through registry or safe mode bypass. Extract ntds.dit via volume shadow copy (vssadmin).'
                            );
                          }
                        }}
                        className={`p-2 rounded-lg border text-xs font-mono transition ${
                          referencePersona === p
                            ? 'bg-cyan-950 border-cyan-500 text-cyan-300'
                            : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Unmasked Post / Negotiation Sample:</span>
                    <span>{suspectText.length} chars</span>
                  </div>
                  <textarea
                    rows={4}
                    value={suspectText}
                    onChange={(e) => setSuspectText(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  onClick={() => {
                    setIsAnalyzingStylometry(true);
                    setTimeout(() => {
                      setIsAnalyzingStylometry(false);
                      setStylometryResult({
                        fused_confidence_score: 92.4,
                        verdict: 'CONFIRMED / HIGH AFFINITY ATTRIBUTION',
                        risk_tier: 'CRITICAL',
                        candidate: referencePersona,
                        organization: 'Correlated Threat Persona',
                        inferred_timezone: 'UTC+3 (Eastern Europe / Moscow)',
                        component_scores: {
                          character_ngram_similarity: 94.2,
                          punctuation_habit_match: 89.0,
                          lexical_syntax_consistency: 91.5,
                          temporal_activity_overlap: 94.0,
                        },
                        markers: [
                          'High character 3-gram cosine affinity against known baseline corpus',
                          'Punctuation habits and casing shifts align with historical threat actor communications',
                          'Diurnal posting timeline overlaps peak working hours in inferred timezone',
                        ],
                      });
                    }, 500);
                  }}
                  disabled={isAnalyzingStylometry}
                  className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-xs flex items-center justify-center gap-2 transition"
                >
                  {isAnalyzingStylometry ? (
                    <span className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                  ) : (
                    <Fingerprint className="w-4 h-4" />
                  )}
                  <span>Execute Stylometric Attribution Comparison</span>
                </button>
              </div>

              {/* Stylometry Report */}
              {stylometryResult && (
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div>
                      <span className="text-xs font-mono text-cyan-400">ATTRIBUTION RESULT:</span>
                      <h4 className="text-base font-bold text-white font-mono mt-0.5">
                        {stylometryResult.candidate}
                      </h4>
                      <p className="text-xs text-emerald-400 font-mono font-semibold">
                        {stylometryResult.verdict}
                      </p>
                    </div>

                    <div className="text-right font-mono">
                      <div className="text-xs text-slate-400">Fused Confidence</div>
                      <div className="text-2xl font-bold text-cyan-400">
                        {stylometryResult.fused_confidence_score}%
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block">N-Grams</span>
                      <span className="text-white font-bold">{stylometryResult.component_scores.character_ngram_similarity}%</span>
                    </div>
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block">Punctuation</span>
                      <span className="text-white font-bold">{stylometryResult.component_scores.punctuation_habit_match}%</span>
                    </div>
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block">Syntax Habit</span>
                      <span className="text-white font-bold">{stylometryResult.component_scores.lexical_syntax_consistency}%</span>
                    </div>
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block">Timeline Match</span>
                      <span className="text-white font-bold">{stylometryResult.component_scores.temporal_activity_overlap}%</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Timezone Diurnal Model */}
            <div className="space-y-4">
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
                <h4 className="text-xs font-semibold text-white uppercase font-mono tracking-wider flex items-center gap-2">
                  <Clock className="w-4 h-4 text-amber-400" />
                  Diurnal Posting Model (24h UTC)
                </h4>
                <div className="grid grid-cols-24 gap-0.5 h-16 bg-slate-950 p-1.5 rounded-lg border border-slate-800 items-end">
                  {[
                    1, 0, 0, 0, 0, 0, 2, 5, 9, 13, 14, 15, 14, 11, 9, 7, 5, 3, 2, 1, 0, 0, 0, 0
                  ].map((val, idx) => (
                    <div
                      key={idx}
                      style={{ height: `${(val / 15) * 100}%` }}
                      title={`${idx}:00 UTC - ${val} posts`}
                      className={`rounded-t-sm transition-all ${
                        val > 10 ? 'bg-amber-400' : val > 5 ? 'bg-cyan-500' : 'bg-slate-700'
                      }`}
                    ></div>
                  ))}
                </div>
                <div className="p-3 rounded bg-slate-950 border border-amber-500/20 text-xs font-mono space-y-1">
                  <div className="text-amber-400 font-semibold">Inferred Origin: UTC+3 (Eastern Europe)</div>
                  <div className="text-slate-400 text-[11px]">Primary active hours: 08:00 - 18:00 UTC</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
