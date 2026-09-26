"""
DeepTrace AI - Module 3: OSINT Knowledge RAG Loop (rag.py)
Autonomous OSINT and Dark Web Threat Actor De-Anonymization Platform

Capabilities:
1. Lightweight, low-memory disk-based semantic vector engine optimized for free cloud tiers (Render, Vercel, HF Spaces).
2. Avoids heavy C-extensions (PyTorch/ONNX/AVX) that trigger SIGILL (exit code 132) crashes on virtualized CPUs.
3. TF-IDF semantic vector space & cosine similarity search via Scikit-Learn.
4. Document ingestion and semantic chunking with metadata tagging (actor, category, MITRE ATT&CK TTPs, source).
5. Pre-seeded tactical de-anonymization intelligence knowledge base:
   - Favicon MurmurHash3 mapping (Shodan standard).
   - TLS/SSL JARM fingerprinting & X.509 Subject Alternative Name (SAN) leakage.
   - Apache /server-status and Nginx stub_status clearnet IP exposure.
   - Tor2Web gateway timing attacks & clock skew correlations.
   - Cryptocurrency wallet clustering (BTC/XMR exchange wash detection).
6. Autonomous similarity querying with relevance distance scoring and contextual answer synthesis.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("DeepTrace.RAG")

# Storage directory for disk-based vector index
RAG_STORAGE_DIR = os.getenv("RAG_STORAGE_DIR", "/tmp/deeptrace_rag")
os.makedirs(RAG_STORAGE_DIR, exist_ok=True)

# Curated OSINT Tactical Knowledge Base Seeds
SEED_TACTICAL_INTELLIGENCE = [
    {
        "id": "tac_001_favicon_mmh3",
        "threat_actor": "General Darknet Infrastructure",
        "category": "Passive Infrastructure Fingerprinting",
        "title": "Favicon MurmurHash3 Tor-to-Clearnet Correlation",
        "content": (
            "Hidden services frequently reuse corporate or clearnet branding assets without sanitization. "
            "By fetching /favicon.ico or icons declared in <link rel='icon'>, encoding the binary content in Base64 "
            "with RFC-2045 line wrapping (every 76 characters), and computing signed 32-bit MurmurHash3 (mmh3), "
            "analysts can match the resulting integer directly against Shodan's `http.favicon.hash:<hash>` index to "
            "reveal clearnet public IPs, hosting providers, and associated domain names."
        ),
        "mitre_technique": "T1592.002 - Gather Victim Host Information",
        "source": "Shodan OSINT Methodology / SANS ISC",
    },
    {
        "id": "tac_002_ssl_san_leak",
        "threat_actor": "Ransomware Affiliates & Phishing Clusters",
        "category": "Cryptographic Misconfiguration",
        "title": "X.509 Subject Alternative Name (SAN) Domain Leakage",
        "content": (
            "When dark web operators configure HTTPS using Let's Encrypt or multi-domain SSL certificates, "
            "they often generate a certificate covering both their clearnet domain (e.g., example.com) and their "
            "onion gateway mirror. Extracting the x509v3 Subject Alternative Name (SAN) extension reveals all hostnames "
            "for which the certificate was issued, instantly establishing an irrefutable link between an anonymous "
            "hidden service and registered clearnet infrastructure."
        ),
        "mitre_technique": "T1588.004 - Digital Certificates",
        "source": "CISA Alert AA23-075A",
    },
    {
        "id": "tac_003_server_status_leak",
        "threat_actor": "Dread & BreachForums Clones",
        "category": "Web Server Exploitation / Leakage",
        "title": "Apache mod_status (/server-status) Public Exposure",
        "content": (
            "Apache HTTP Server's mod_status module provides a human-readable /server-status dashboard. "
            "Misconfigured hidden services that fail to restrict access to localhost expose the server's public IP address, "
            "clearnet VirtualHost entries (VHost directive), current client IP addresses, and active HTTP request URIs, "
            "completely dismantling the anonymity provided by the Tor routing circuit."
        ),
        "mitre_technique": "T1592 - Gather Victim Host Information",
        "source": "Recorded Future Dark Web Research",
    },
    {
        "id": "tac_004_clock_skew_timing",
        "threat_actor": "State-Sponsored APTs (Labyrinth Chollima / Sandworm)",
        "category": "Temporal Analysis",
        "title": "HTTP Date Header Clock Skew & Uptime Correlation",
        "content": (
            "Analyzing high-resolution HTTP response headers such as 'Date', 'ETag', and TCP timestamps enables "
            "correlating dark web servers with public clearnet web servers exhibiting identical millisecond clock drift "
            "and boot uptime signatures, identifying instances hosted on shared multi-homed VPS hardware."
        ),
        "mitre_technique": "T1590.005 - IP Addresses",
        "source": "USENIX Security Symposium",
    },
    {
        "id": "tac_005_crypto_clustering",
        "threat_actor": "LockBitSupp & BlackCat/ALPHV",
        "category": "Financial OSINT",
        "title": "Common-Input Ownership Heuristic in Ransomware Payments",
        "content": (
            "In Bitcoin-based ransomware operations, when multiple inputs are combined in a single transaction, "
            "the common-input ownership heuristic dictates that all input addresses belong to the same entity. "
            "Tracing change outputs and clustering co-spent inputs across dark web negotiation chats reliably correlates "
            "unmasked deposit addresses at KYC-compliant exchanges (Binance, Coinbase, Kraken)."
        ),
        "mitre_technique": "T1588.006 - Financial Accounts",
        "source": "Chainalysis Threat Intelligence",
    },
]


class DiskVectorStore:
    """
    High-performance, low-memory vector store using Scikit-Learn TF-IDF + Cosine similarity.
    Requires < 40MB of RAM, saves to JSON on disk, and has zero illegal instruction (SIGILL 132) risks.
    """

    def __init__(self, storage_file: str):
        self.storage_file = storage_file
        self.documents: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    self.documents = json.load(f)
                logger.info(f"Loaded {len(self.documents)} knowledge documents from disk store.")
            except Exception as e:
                logger.warning(f"Failed to load disk store: {e}")
                self.documents = []
        else:
            self.documents = []

    def _save(self):
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump(self.documents, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save disk vector store: {e}")

    def add_document(self, doc_id: str, content: str, metadata: Dict[str, Any]):
        self.documents = [d for d in self.documents if d["id"] != doc_id]
        self.documents.append({
            "id": doc_id,
            "content": content,
            "metadata": metadata,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._save()

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        if not self.documents:
            return []

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity

            corpus = [doc["content"] + " " + json.dumps(doc.get("metadata", {})) for doc in self.documents]
            vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", lowercase=True)
            tfidf_matrix = vectorizer.fit_transform(corpus)
            query_vec = vectorizer.transform([query])
            similarities = cosine_similarity(query_vec, tfidf_matrix)[0]

            scored = []
            for idx, sim in enumerate(similarities):
                doc = self.documents[idx]
                meta = doc.get("metadata", {})
                score = float(sim)

                if meta.get("threat_actor", "").lower() in query.lower():
                    score += 0.3
                if meta.get("category", "").lower() in query.lower():
                    score += 0.2

                if score > 0.05:
                    final_score = min(0.99, max(0.1, score))
                    scored.append({
                        "id": doc["id"],
                        "content": doc["content"],
                        "metadata": doc["metadata"],
                        "similarity_score": round(final_score, 3),
                        "relevance_distance": round(1.0 - final_score, 3),
                    })

            scored.sort(key=lambda x: x["similarity_score"], reverse=True)
            return scored[:top_k]

        except Exception as e:
            logger.warning(f"TF-IDF search error: {e}. Falling back to token intersection.")
            query_tokens = set(query.lower().split())
            scored = []
            for doc in self.documents:
                doc_text = (doc["content"] + " " + json.dumps(doc.get("metadata", {}))).lower()
                doc_tokens = set(doc_text.split())
                intersection = query_tokens.intersection(doc_tokens)
                score = len(intersection) / max(1, len(query_tokens))
                if score > 0:
                    scored.append({
                        "id": doc["id"],
                        "content": doc["content"],
                        "metadata": doc["metadata"],
                        "similarity_score": round(min(0.99, score), 3),
                        "relevance_distance": round(1.0 - min(0.99, score), 3),
                    })
            scored.sort(key=lambda x: x["similarity_score"], reverse=True)
            return scored[:top_k]


class OSINTKnowledgeRAG:
    """
    Autonomous OSINT Knowledge RAG Engine.
    Employs disk-based TF-IDF vector space index for maximum compatibility
    across minimal cloud hosts (Render free tier, Vercel, HF Spaces).
    """

    def __init__(self, persist_dir: str = RAG_STORAGE_DIR):
        self.persist_dir = persist_dir
        self.storage_file = os.path.join(self.persist_dir, "osint_knowledge_index.json")
        self.vector_store = DiskVectorStore(self.storage_file)
        self._seed_default_intelligence()

    def _seed_default_intelligence(self):
        for item in SEED_TACTICAL_INTELLIGENCE:
            self.learn(
                doc_id=item["id"],
                content=item["content"],
                threat_actor=item["threat_actor"],
                category=item["category"],
                source=item["source"],
                extra_metadata={"mitre_technique": item["mitre_technique"], "title": item["title"]},
            )

    def learn(
        self,
        content: str,
        threat_actor: str,
        category: str,
        source: str = "Scraped OSINT Feed",
        doc_id: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not doc_id:
            doc_id = f"doc_{hashlib.sha256((threat_actor + content[:50]).encode()).hexdigest()[:12]}"

        metadata = {
            "threat_actor": threat_actor,
            "category": category,
            "source": source,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }
        if extra_metadata:
            metadata.update(extra_metadata)

        self.vector_store.add_document(doc_id, content, metadata)

        logger.info(f"Ingested intelligence record [{doc_id}] for actor '{threat_actor}'")
        return {
            "status": "INGESTED",
            "document_id": doc_id,
            "threat_actor": threat_actor,
            "category": category,
            "backend": "Disk TF-IDF Vector Space",
        }

    def query(self, search_query: str, top_k: int = 4) -> Dict[str, Any]:
        results = self.vector_store.search(search_query, top_k=top_k)

        tactical_summary = []
        for r in results:
            meta = r.get("metadata", {})
            title = meta.get("title", meta.get("category", "OSINT Vector"))
            actor = meta.get("threat_actor", "General")
            tactical_summary.append(f"[{title}] Applied against {actor} (Relevance: {int(r['similarity_score'] * 100)}%)")

        return {
            "query": search_query,
            "total_matches": len(results),
            "backend_engine": "Disk TF-IDF Semantic Vector Space (Low-RAM / Zero-Crash)",
            "matches": results,
            "tactical_summary": tactical_summary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


if __name__ == "__main__":
    rag = OSINTKnowledgeRAG()
    res = rag.query("favicon mmh3 Shodan hash")
    print(f"Matched {res['total_matches']} records via {res['backend_engine']}")
