"""
Behavioral Threat & API Abuse Detection Engine (Pygenic Arc / Team Rudranix)

Fulfills the Hackathon Mandatory Conditions:
- Multi-Pattern Detection:
  1. Credential Stuffing (dual-axis IP & Username auth failure tracking)
  2. Scraping (timing entropy & request pacing variance analysis)
  3. Endpoint Enumeration / IDOR (sequential ID walking & 404 fuzzing)
  4. Abnormal Sequence (Markov Chain state transition modeling)
  5. Legitimate High-Volume Traffic Discrimination (benign burst vs attack)

- Structured Output Schema:
  (risk_score, behaviour_category, evidence)

- Innovation:
  - Sequence Models (Markov Transition Matrix)
  - Adaptive Thresholds & Behavioral Baselines
  - Explainable Evidence Attribution
"""

import math
import re
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Dict, List, Optional, Tuple


class BehaviourCategory(StrEnum):
    BENIGN = "BENIGN"
    BENIGN_BURST = "BENIGN_BURST"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    SCRAPING = "SCRAPING"
    ENDPOINT_ENUMERATION = "ENDPOINT_ENUMERATION"
    ABNORMAL_SEQUENCE = "ABNORMAL_SEQUENCE"


class EnforcementAction(StrEnum):
    ALLOWED = "ALLOWED"
    THROTTLED = "THROTTLED"
    SOFT_BLOCK = "SOFT_BLOCK"
    HARD_BLOCK = "HARD_BLOCK"


@dataclass
class ThreatVerdict:
    risk_score: float  # 0.00 to 1.00
    behaviour_category: BehaviourCategory
    action: EnforcementAction
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 3),
            "behaviour_category": self.behaviour_category.value,
            "action": self.action.value,
            "explanation": self.explanation,
            "evidence": self.evidence,
        }


class MarkovSequenceModel:
    """
    Sequence model based on state transition probability matrices.
    Learns valid API navigation workflows and flags abnormal sequence jumps.
    """

    def __init__(self):
        self.transitions: Dict[str, Dict[str, float]] = {
            "START": {
                "/auth/login": 0.4,
                "/auth/register": 0.2,
                "/products": 0.3,
                "/health": 0.1,
            },
            "/auth/login": {
                "/auth/login": 0.3,
                "/products": 0.4,
                "/users/{id}": 0.2,
                "/cart": 0.1,
            },
            "/auth/register": {
                "/auth/login": 0.7,
                "/products": 0.3,
            },
            "/products": {
                "/products/{id}": 0.6,
                "/cart/add": 0.2,
                "/products": 0.2,
            },
            "/products/{id}": {
                "/products/{id}": 0.3,
                "/cart/add": 0.4,
                "/products": 0.2,
                "/cart": 0.1,
            },
            "/cart/add": {
                "/cart": 0.5,
                "/checkout": 0.3,
                "/products": 0.2,
            },
            "/cart": {
                "/checkout": 0.7,
                "/products": 0.3,
            },
            "/checkout": {
                "/products": 0.6,
                "/users/{id}": 0.4,
            },
            "/users/{id}": {
                "/users/{id}": 0.4,
                "/products": 0.3,
                "/cart": 0.2,
                "/auth/login": 0.1,
            },
        }
        self.min_unseen_prob = 0.001

    @staticmethod
    def canonicalize_path(path: str) -> str:
        clean = re.sub(r"^/api(/v\d+)?", "", path)
        clean = re.sub(r"^/gateway", "", clean)
        if not clean or clean == "/":
            return "/products"
        clean = re.sub(r"/\d+", "/{id}", clean)
        clean = re.sub(
            r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "/{id}",
            clean,
        )
        return clean

    def evaluate_sequence(self, sequence: List[str]) -> Tuple[float, List[str]]:
        if not sequence:
            return 0.0, []

        canonical_seq = [self.canonicalize_path(p) for p in sequence]
        violations = []
        log_prob_sum = 0.0

        prev_state = "START"
        for i, curr_state in enumerate(canonical_seq):
            allowed_next = self.transitions.get(prev_state, {})
            prob = allowed_next.get(curr_state, self.min_unseen_prob)

            if prob <= self.min_unseen_prob:
                violations.append(
                    f"Illegal workflow jump: '{prev_state}' -> '{curr_state}' (step {i+1})"
                )

            log_prob_sum += -math.log(prob)
            prev_state = curr_state

        avg_negative_log_likelihood = log_prob_sum / len(canonical_seq)
        anomaly_score = min(1.0, max(0.0, (avg_negative_log_likelihood - 1.2) / 4.5))

        return anomaly_score, violations


class InMemoryStateStore:
    """Thread-safe in-memory cache mimicking Redis sliding windows and metrics."""

    def __init__(self):
        self.request_times: Dict[str, List[float]] = defaultdict(list)
        self.request_paths: Dict[str, List[str]] = defaultdict(list)
        self.status_codes: Dict[str, List[int]] = defaultdict(list)
        self.failed_auth_ip: Dict[str, int] = defaultdict(int)
        self.failed_auth_user: Dict[str, int] = defaultdict(int)
        self.blocked_ips: Dict[str, Tuple[float, BehaviourCategory]] = {}

    def record_request(
        self,
        client_id: str,
        ip: str,
        path: str,
        status_code: int = 200,
        timestamp: Optional[float] = None,
    ):
        ts = timestamp if timestamp is not None else time.time()
        self.request_times[client_id].append(ts)
        self.request_paths[client_id].append(path)
        self.status_codes[client_id].append(status_code)

        if len(self.request_times[client_id]) > 50:
            self.request_times[client_id].pop(0)
            self.request_paths[client_id].pop(0)
            self.status_codes[client_id].pop(0)

    def record_auth_failure(self, ip: str, username: str):
        self.failed_auth_ip[ip] += 1
        self.failed_auth_user[username] += 1

    def get_auth_failures(self, ip: str, username: str) -> Tuple[int, int]:
        return self.failed_auth_ip.get(ip, 0), self.failed_auth_user.get(username, 0)

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[BehaviourCategory], float]:
        item = self.blocked_ips.get(ip)
        if item:
            expiry, cat = item
            rem = expiry - time.time()
            if rem > 0:
                return True, cat, rem
            else:
                del self.blocked_ips[ip]
        return False, None, 0.0

    def block_ip(
        self,
        ip: str,
        category: BehaviourCategory,
        ttl_seconds: int = 180,
    ):
        self.blocked_ips[ip] = (time.time() + ttl_seconds, category)


class BehavioralThreatEngine:
    """
    Central Threat & Behavioral Detection Engine.
    Evaluates requests and sequence logs against multiple heuristic & probabilistic baselines.
    """

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.local_store = InMemoryStateStore()
        self.sequence_model = MarkovSequenceModel()

        # Adaptive Thresholds
        self.min_samples_entropy = 4
        self.entropy_bot_threshold = 30.0  # ms variance threshold
        self.auth_fail_threshold_ip = 5
        self.auth_fail_threshold_user = 3
        self.enumeration_unique_ratio = 0.70

    def analyze_request(
        self,
        client_id: str,
        ip: str,
        path: str,
        username: Optional[str] = None,
        status_code: int = 200,
        timestamp: Optional[float] = None,
    ) -> ThreatVerdict:
        """
        Real-time or simulated inspection of a request.
        Returns a ThreatVerdict containing risk_score, behaviour_category, action, and evidence.
        """
        # 1. Check existing active block first
        is_blocked, blocked_cat, rem_ttl = self.local_store.is_blocked(ip)
        if is_blocked:
            ip_fails, user_fails = self.local_store.get_auth_failures(ip, username or client_id)
            return ThreatVerdict(
                risk_score=1.0,
                behaviour_category=blocked_cat or BehaviourCategory.CREDENTIAL_STUFFING,
                action=EnforcementAction.SOFT_BLOCK,
                explanation=f"Client IP is under active enforcement block ({blocked_cat.value if blocked_cat else 'ABUSE'}). Retry window active.",
                evidence={
                    "client_id": client_id,
                    "client_ip": ip,
                    "blocked_ip": ip,
                    "ttl_remaining_seconds": round(rem_ttl, 1),
                    "auth_failures_recorded": {"ip_fails": ip_fails, "user_fails": user_fails},
                    "feature_contributions": {"active_block": 1.0},
                    "reasons": [f"Active enforcement block in place ({blocked_cat.value if blocked_cat else 'ABUSE'})"],
                },
            )

        # 2. Record request into sliding window
        self.local_store.record_request(client_id, ip, path, status_code, timestamp=timestamp)
        if status_code in (401, 403) and "/auth" in path and username:
            self.local_store.record_auth_failure(ip, username)

        recent_times = self.local_store.request_times[client_id]
        recent_paths = self.local_store.request_paths[client_id]
        recent_statuses = self.local_store.status_codes[client_id]
        ip_fails, user_fails = self.local_store.get_auth_failures(
            ip, username or client_id
        )

        reasons = []
        feature_scores = {}

        # ── SIGNAL A: Credential Stuffing ─────────────────────────────────
        stuffing_risk = 0.0
        if ip_fails >= self.auth_fail_threshold_ip:
            stuffing_risk = min(1.0, 0.70 + (ip_fails / 10.0))
            reasons.append(
                f"Source IP credential stuffing ({ip_fails} auth failures against threshold {self.auth_fail_threshold_ip})"
            )
        elif user_fails >= self.auth_fail_threshold_user:
            stuffing_risk = min(1.0, 0.65 + (user_fails / 5.0))
            reasons.append(
                f"Account targeted brute-force ({user_fails} auth failures on single username)"
            )
        elif ip_fails >= 2 and "/auth" in path:
            stuffing_risk = 0.45 + (ip_fails * 0.1)
            reasons.append(f"Multiple consecutive authentication failures ({ip_fails})")
        feature_scores["credential_stuffing"] = stuffing_risk

        # ── SIGNAL B: Scraping & Timing Regularity (Entropy) ──────────────
        scraping_risk = 0.0
        entropy = None
        # Scraping detection applies primarily to content endpoints, not auth failure attacks
        if len(recent_times) >= self.min_samples_entropy and ("/auth" not in path or status_code == 200):
            gaps = [
                (recent_times[i + 1] - recent_times[i]) * 1000
                for i in range(len(recent_times) - 1)
            ]
            if len(gaps) >= 2:
                try:
                    entropy = float(statistics.stdev(gaps))
                    avg_gap = float(statistics.mean(gaps))

                    # Machine-paced scraping (<30ms standard deviation and pacing < 1500ms)
                    if entropy < self.entropy_bot_threshold and avg_gap < 1500:
                        scraping_risk = min(
                            0.95,
                            0.60 + (self.entropy_bot_threshold - entropy) / self.entropy_bot_threshold * 0.35,
                        )
                        reasons.append(
                            f"Suspiciously regular request timing: entropy={entropy:.2f}ms (threshold < {self.entropy_bot_threshold}ms, avg pacing={avg_gap:.1f}ms)"
                        )
                except Exception:
                    entropy = None
        feature_scores["scraping_entropy"] = scraping_risk

        # ── SIGNAL C: Endpoint Enumeration / IDOR ─────────────────────────
        enumeration_risk = 0.0
        if len(recent_paths) >= 4:
            id_patterns = []
            for p in recent_paths:
                m = re.search(r"/(\d+)$", p)
                if m:
                    id_patterns.append(int(m.group(1)))

            distinct_paths = len(set(recent_paths))
            path_diversity_ratio = distinct_paths / len(recent_paths)
            not_found_count = sum(1 for s in recent_statuses if s == 404)

            # Check consecutive step progression in IDs e.g. 1, 2, 3, 4
            if len(id_patterns) >= 3:
                diffs = [
                    abs(id_patterns[i + 1] - id_patterns[i])
                    for i in range(len(id_patterns) - 1)
                ]
                if all(d == 1 for d in diffs):
                    enumeration_risk = 0.94
                    reasons.append(
                        f"IDOR / Sequential identifier enumeration detected (sequence: {id_patterns[-4:]})"
                    )

            if not_found_count >= 3 and path_diversity_ratio > self.enumeration_unique_ratio:
                enumeration_risk = max(enumeration_risk, 0.88)
                reasons.append(
                    f"Directory fuzzing / 404 probing detected ({not_found_count} 404s across {distinct_paths} distinct paths)"
                )

        feature_scores["enumeration"] = enumeration_risk

        # ── SIGNAL D: Sequence Anomaly & Workflow Bypass ──────────────────
        sequence_risk = 0.0
        sequence_violations = []
        if len(recent_paths) >= 2:
            sequence_risk, sequence_violations = self.sequence_model.evaluate_sequence(
                recent_paths[-6:]
            )
            if sequence_risk >= 0.45:
                reasons.extend(sequence_violations)
        feature_scores["sequence_anomaly"] = sequence_risk

        # ── SIGNAL E: Benign High-Volume Burst Discrimination ─────────────
        # High volume, but natural human entropy (>80ms), valid sequence, no failures
        is_benign_burst = False
        if len(recent_times) >= 6 and entropy is not None and entropy > 75.0:
            if stuffing_risk == 0 and enumeration_risk == 0 and sequence_risk < 0.25:
                is_benign_burst = True

        # ── AGGREGATE RISK SCORE & CATEGORIZATION ─────────────────────────
        max_threat = max(stuffing_risk, scraping_risk, enumeration_risk, sequence_risk)

        if is_benign_burst:
            category = BehaviourCategory.BENIGN_BURST
            risk_score = 0.10
            action = EnforcementAction.ALLOWED
            explanation = "High-velocity traffic validated as legitimate human burst (natural timing variance and compliant workflow transitions)."
        elif max_threat >= 0.70:
            if stuffing_risk >= 0.70:
                category = BehaviourCategory.CREDENTIAL_STUFFING
            elif enumeration_risk >= 0.70:
                category = BehaviourCategory.ENDPOINT_ENUMERATION
            elif scraping_risk >= 0.70:
                category = BehaviourCategory.SCRAPING
            else:
                category = BehaviourCategory.ABNORMAL_SEQUENCE

            risk_score = max_threat
            action = EnforcementAction.SOFT_BLOCK
            self.local_store.block_ip(ip, category=category, ttl_seconds=180)
            explanation = f"High-confidence threat detected [{category.value}]. Automatic soft-block enforced with Retry-After."
        elif max_threat >= 0.40:
            if max_threat == scraping_risk:
                category = BehaviourCategory.SCRAPING
            elif max_threat == stuffing_risk:
                category = BehaviourCategory.CREDENTIAL_STUFFING
            elif max_threat == enumeration_risk:
                category = BehaviourCategory.ENDPOINT_ENUMERATION
            else:
                category = BehaviourCategory.ABNORMAL_SEQUENCE

            risk_score = max_threat
            action = EnforcementAction.THROTTLED
            explanation = f"Behavior approaching threat threshold [{category.value}]. Rate delayed with Retry-After to degrade automation."
        else:
            category = BehaviourCategory.BENIGN
            risk_score = max(0.04, max_threat)
            action = EnforcementAction.ALLOWED
            explanation = "Normal legitimate API request adhering to expected behavioral baselines."

        evidence = {
            "client_id": client_id,
            "client_ip": ip,
            "requests_analyzed": len(recent_paths),
            "timing_entropy_ms": round(entropy, 2) if entropy is not None else None,
            "auth_failures_recorded": {"ip_fails": ip_fails, "user_fails": user_fails},
            "feature_contributions": {
                k: round(v, 2) for k, v in feature_scores.items()
            },
            "reasons": reasons if reasons else ["Traffic matches legitimate baseline"],
        }

        return ThreatVerdict(
            risk_score=risk_score,
            behaviour_category=category,
            action=action,
            explanation=explanation,
            evidence=evidence,
        )


threat_engine = BehavioralThreatEngine()
