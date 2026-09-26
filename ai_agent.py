"""
DeepTrace AI - Module 4: Stylometry & Timeline AI Core (ai_agent.py)
Autonomous OSINT and Dark Web Threat Actor De-Anonymization Platform

Capabilities:
1. TF-IDF Character n-grams (ranges 2-5) extraction via Scikit-Learn.
2. Punctuation vector analysis, casing habits, and lexical richness (Type-Token Ratio).
3. 24-Hour UTC posting frequency analysis and diurnal waking-hour timezone inference.
4. Mathematical overlap calculation (Bhattacharyya coefficient & Cosine similarity).
5. Fused attribution confidence scoring (Stylometry + Temporal + Syntax).
6. Pre-configured forensic catalog of notorious threat actor writing profiles
   (LockBitSupp, Pompompurin, Bassterlord, LabyrinthChollima).
"""

import math
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("DeepTrace.Stylometry")

# Fallback TF-IDF vectorizer if scikit-learn is unavailable or in minimal mode
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("Scikit-Learn not found. Activating pure-Python TF-IDF vector math fallback.")


# Known Dark Web Threat Actor Corpus Profiles (for automated benchmark attribution)
KNOWN_THREAT_ACTOR_PROFILES = {
    "LockBitSupp": {
        "alias": "LockBitSupp",
        "organization": "LockBit Ransomware Syndicate",
        "inferred_timezone": "UTC+3 (Eastern Europe / Moscow)",
        "sample_text": (
            "We pay 1 million dollars for any information leading to FBI agent names! "
            "Our affiliate program is the most stable and honest in the world. "
            "If your company is encrypted, contact us via tox or our onion chat immediately. "
            "Do not trust recovery companies, they take your money and pay us anyway. "
            "Guaranteed decryptor test on 1 file for free. Make money with LockBit 3.0!"
        ),
        # 24-hour UTC posting distribution (0 to 23)
        "hourly_distribution": [
            1, 0, 0, 0, 0, 0, 1, 4, 8, 12, 14, 15, 14, 12, 10, 8, 6, 4, 2, 1, 0, 0, 0, 0
        ],
    },
    "Pompompurin": {
        "alias": "Pompompurin",
        "organization": "BreachForums / RaidForums Admin",
        "inferred_timezone": "UTC-5 (US Eastern)",
        "sample_text": (
            "hey guys, welcome back to the new forum. keep all sales in the marketplace section "
            "and use escrow if you don't know the seller. don't dm me about bans, post an appeal. "
            "also please stop asking about database leaks that aren't verified yet. thanks and enjoy."
        ),
        "hourly_distribution": [
            10, 12, 14, 11, 7, 2, 0, 0, 0, 0, 1, 2, 4, 5, 7, 9, 11, 12, 13, 14, 15, 14, 12, 11
        ],
    },
    "Bassterlord": {
        "alias": "Bassterlord",
        "organization": "National Ransomware Instructor / Conti Affiliate",
        "inferred_timezone": "UTC+2 / UTC+3 (Eastern Europe)",
        "sample_text": (
            "Manual on network compromise and AD enumeration: Always disable Defender through "
            "registry or safe mode bypass. Extract ntds.dit via volume shadow copy (vssadmin). "
            "Do not rush payload deployment until exfiltration over rclone is 100% finished. "
            "Respect the targets and do not touch healthcare."
        ),
        "hourly_distribution": [
            0, 0, 0, 0, 1, 3, 7, 11, 13, 15, 16, 15, 13, 11, 8, 5, 3, 1, 0, 0, 0, 0, 0, 0
        ],
    },
    "LabyrinthChollima": {
        "alias": "LabyrinthChollima",
        "organization": "Lazarus Group / DPRK Reconnaissance Bureau",
        "inferred_timezone": "UTC+9 (Pyongyang / KST)",
        "sample_text": (
            "Kindly find attached urgent job specification for Senior Smart Contract Engineer position. "
            "Please review the coding challenge inside the zip archive and execute the build test. "
            "We offer competitive compensation in USDT. Let us know your availability for interview."
        ),
        "hourly_distribution": [
            9, 13, 15, 14, 12, 8, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 6, 8, 10, 11, 10, 9
        ],
    },
}


class StylometryTimelineAgent:
    """
    Advanced NLP Stylometry & Chrono-Location Agent.
    Unmasks threat actor personas across darknet forums through forensic writing style analysis
    and UTC activity timeline correlation.
    """

    def __init__(self, ngram_range: Tuple[int, int] = (2, 5)):
        self.ngram_range = ngram_range
        if SKLEARN_AVAILABLE:
            self.char_vectorizer = TfidfVectorizer(
                analyzer="char",
                ngram_range=self.ngram_range,
                min_df=1,
                lowercase=True,
            )
        else:
            self.char_vectorizer = None

    @staticmethod
    def extract_punctuation_vector(text: str) -> Dict[str, float]:
        """Calculates normalized punctuation frequencies."""
        punct_marks = [".", ",", "!", "?", ";", ":", "-", "(", ")", '"', "'", "..."]
        total_chars = max(1, len(text))
        profile = {}
        for p in punct_marks:
            profile[p] = text.count(p) / total_chars * 100.0
        return profile

    @staticmethod
    def extract_casing_and_richness(text: str) -> Dict[str, float]:
        """Calculates capitalization ratios and vocabulary richness (Type-Token Ratio)."""
        words = [w.strip(".,!?:;\"'()[]{}") for w in text.split() if w.strip()]
        total_words = max(1, len(words))
        unique_words = len(set(w.lower() for w in words))
        ttr = unique_words / total_words  # Lexical Richness

        caps_chars = sum(1 for c in text if c.isupper())
        total_letters = max(1, sum(1 for c in text if c.isalpha()))
        caps_ratio = caps_chars / total_letters

        # Screaming word count (ALL CAPS words longer than 2 chars)
        screaming_words = sum(1 for w in words if len(w) > 2 and w.isupper())

        return {
            "type_token_ratio": round(ttr, 3),
            "capitalization_ratio": round(caps_ratio, 3),
            "screaming_words_count": screaming_words,
            "avg_word_length": round(sum(len(w) for w in words) / total_words, 2),
            "total_word_count": total_words,
        }

    def compute_char_ngram_similarity(self, text_a: str, text_b: str) -> float:
        """
        Computes cosine similarity of TF-IDF character n-grams between two writing samples.
        """
        if not text_a or not text_b:
            return 0.0

        if SKLEARN_AVAILABLE:
            try:
                tfidf_matrix = self.char_vectorizer.fit_transform([text_a, text_b])
                sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
                return float(sim)
            except Exception as e:
                logger.warning(f"Sklearn TF-IDF failed: {e}. Falling back to n-gram set similarity.")

        # Robust pure-Python fallback (n-gram intersection)
        n = 3
        clean_a = "".join(c.lower() for c in text_a if c.isalnum() or c.isspace())
        clean_b = "".join(c.lower() for c in text_b if c.isalnum() or c.isspace())

        grams_a = {}
        for i in range(len(clean_a) - n + 1):
            g = clean_a[i : i + n]
            grams_a[g] = grams_a.get(g, 0) + 1

        grams_b = {}
        for i in range(len(clean_b) - n + 1):
            g = clean_b[i : i + n]
            grams_b[g] = grams_b.get(g, 0) + 1

        all_grams = set(grams_a.keys()).union(set(grams_b.keys()))
        dot = sum(grams_a.get(g, 0) * grams_b.get(g, 0) for g in all_grams)
        norm_a = math.sqrt(sum(v * v for v in grams_a.values()))
        norm_b = math.sqrt(sum(v * v for v in grams_b.values()))

        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    @staticmethod
    def infer_primary_timezone(hourly_distribution: List[int]) -> Dict[str, Any]:
        """
        Infers likely UTC timezone offset (UTC-12 to UTC+14) based on diurnal activity.
        Assumes standard human wakefulness / peak cyber operations occur between 09:00 and 22:00 local time.
        """
        if len(hourly_distribution) != 24 or sum(hourly_distribution) == 0:
            return {
                "inferred_offset": 0,
                "inferred_timezone_label": "UTC+0 (Undetermined)",
                "peak_hour_utc": 12,
                "confidence": 30.0,
            }

        # Normalize hourly distribution
        total = sum(hourly_distribution)
        normalized = [h / total for h in hourly_distribution]

        # Find peak 8-hour consecutive activity window
        best_window_score = -1.0
        best_start_hour = 0
        for start_h in range(24):
            window_sum = sum(normalized[(start_h + i) % 24] for i in range(8))
            if window_sum > best_window_score:
                best_window_score = window_sum
                best_start_hour = start_h

        peak_center_utc = (best_start_hour + 4) % 24

        # Map peak center to local 14:00 (midday cyber operational peak)
        target_local_hour = 14
        offset = (target_local_hour - peak_center_utc) % 24
        if offset > 12:
            offset -= 24

        tz_labels = {
            -8: "UTC-8 (US Pacific)",
            -5: "UTC-5 (US Eastern)",
            -3: "UTC-3 (Brazil / South America)",
            0: "UTC+0 (London / Western Europe)",
            1: "UTC+1 (Central European Time)",
            2: "UTC+2 (Eastern Europe / Kyiv)",
            3: "UTC+3 (Moscow / Minsk)",
            4: "UTC+4 (Caucasus / Gulf)",
            5: "UTC+5 (Central Asia / Yekaterinburg)",
            8: "UTC+8 (Beijing / Singapore)",
            9: "UTC+9 (Pyongyang / Tokyo / Seoul)",
        }

        label = tz_labels.get(offset, f"UTC{'+' if offset >= 0 else ''}{offset}")

        return {
            "inferred_offset": offset,
            "inferred_timezone_label": label,
            "peak_hour_utc": peak_center_utc,
            "window_concentration": round(best_window_score * 100, 1),
        }

    @staticmethod
    def compute_temporal_overlap(dist_a: List[int], dist_b: List[int]) -> float:
        """
        Computes Bhattacharyya / Cosine histogram affinity between two 24-hour activity timelines.
        """
        if not dist_a or not dist_b or len(dist_a) != 24 or len(dist_b) != 24:
            return 0.5

        sum_a = sum(dist_a)
        sum_b = sum(dist_b)
        if sum_a == 0 or sum_b == 0:
            return 0.5

        p_a = [x / sum_a for x in dist_a]
        p_b = [y / sum_b for y in dist_b]

        # Bhattacharyya coefficient: sum(sqrt(p_a * p_b))
        bc = sum(math.sqrt(p_a[i] * p_b[i]) for i in range(24))
        return min(1.0, max(0.0, bc))

    def attribute(
        self,
        suspect_text: str,
        reference_text: str,
        suspect_hours: Optional[List[int]] = None,
        reference_hours: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Executes unified Stylometry & Timeline attribution comparison between two entities.
        Returns comprehensive forensic breakdown and fused attribution percentage.
        """
        # 1. Stylometry Character N-gram affinity
        ngram_affinity = self.compute_char_ngram_similarity(suspect_text, reference_text)

        # 2. Punctuation Profile comparison
        punct_a = self.extract_punctuation_vector(suspect_text)
        punct_b = self.extract_punctuation_vector(reference_text)
        punct_diffs = [abs(punct_a[k] - punct_b[k]) for k in punct_a]
        avg_punct_delta = sum(punct_diffs) / max(1, len(punct_diffs))
        punct_match = max(0.0, 1.0 - (avg_punct_delta / 2.0))

        # 3. Casing & Richness Habits
        lex_a = self.extract_casing_and_richness(suspect_text)
        lex_b = self.extract_casing_and_richness(reference_text)
        casing_delta = abs(lex_a["capitalization_ratio"] - lex_b["capitalization_ratio"])
        ttr_delta = abs(lex_a["type_token_ratio"] - lex_b["type_token_ratio"])
        syntax_match = max(0.0, 1.0 - (casing_delta * 3.0 + ttr_delta * 0.5))

        # 4. Temporal 24h Activity Analysis
        temporal_match = 0.80  # Default baseline if hours unavailable
        tz_analysis_suspect = None
        tz_analysis_ref = None

        if suspect_hours and reference_hours:
            temporal_match = self.compute_temporal_overlap(suspect_hours, reference_hours)
            tz_analysis_suspect = self.infer_primary_timezone(suspect_hours)
            tz_analysis_ref = self.infer_primary_timezone(reference_hours)

        # 5. Fused Confidence Metric
        # Weighted: 45% Stylometry N-grams, 20% Punctuation & Syntax, 35% Temporal Timeline
        fused = (
            ngram_affinity * 0.45
            + ((punct_match + syntax_match) / 2.0) * 0.20
            + temporal_match * 0.35
        ) * 100.0

        fused = round(min(99.0, max(5.0, fused)), 1)

        # Forensic Qualitative Classification
        if fused >= 80.0:
            verdict = "CONFIRMED / HIGH AFFINITY ATTRIBUTION"
            risk_tier = "CRITICAL"
        elif fused >= 60.0:
            verdict = "PROBABLE PERSONA ALIASING"
            risk_tier = "HIGH"
        elif fused >= 40.0:
            verdict = "MODERATE / CIRCUMSTANTIAL SIMILARITY"
            risk_tier = "MEDIUM"
        else:
            verdict = "LOW / UNRELATED PERSONAS"
            risk_tier = "LOW"

        return {
            "fused_confidence_score": fused,
            "verdict": verdict,
            "risk_tier": risk_tier,
            "component_scores": {
                "character_ngram_similarity": round(ngram_affinity * 100, 1),
                "punctuation_habit_match": round(punct_match * 100, 1),
                "lexical_syntax_consistency": round(syntax_match * 100, 1),
                "temporal_activity_overlap": round(temporal_match * 100, 1),
            },
            "lexical_profiles": {
                "suspect": lex_a,
                "reference": lex_b,
            },
            "timezone_intelligence": {
                "suspect": tz_analysis_suspect,
                "reference": tz_analysis_ref,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def correlate_against_catalog(
        self,
        suspect_text: str,
        suspect_hours: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Compares an unknown suspect persona against all known Dark Web threat actors in catalog.
        Returns ranked list of candidate personas sorted by fused confidence.
        """
        rankings = []
        for alias, profile in KNOWN_THREAT_ACTOR_PROFILES.items():
            res = self.attribute(
                suspect_text=suspect_text,
                reference_text=profile["sample_text"],
                suspect_hours=suspect_hours,
                reference_hours=profile["hourly_distribution"],
            )
            rankings.append({
                "candidate_alias": alias,
                "organization": profile["organization"],
                "known_timezone": profile["inferred_timezone"],
                "fused_confidence": res["fused_confidence_score"],
                "verdict": res["verdict"],
                "component_scores": res["component_scores"],
            })

        rankings.sort(key=lambda x: x["fused_confidence"], reverse=True)
        return rankings


# Quick standalone validation
if __name__ == "__main__":
    agent = StylometryTimelineAgent()
    sample = (
        "We are launching our new affiliate program! 20% commission, automated Tox chat "
        "and clean decryptors. Contact LockBitSupp immediately or face full leak."
    )
    test_hours = [1, 0, 0, 0, 0, 0, 2, 5, 9, 13, 14, 15, 14, 11, 9, 7, 5, 3, 2, 1, 0, 0, 0, 0]

    print("[*] Running Catalog Attribution Correlator...")
    results = agent.correlate_against_catalog(sample, test_hours)
    for r in results:
        print(f" - {r['candidate_alias']} ({r['organization']}): {r['fused_confidence']}% [{r['verdict']}]")
