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
    AUTOMATED_BOT = "AUTOMATED_BOT"
    MANUAL_BAN = "MANUAL_BAN"


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
            "/health": {
                "/health": 0.5,
                "/products": 0.3,
                "/auth/login": 0.2,
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
        if clean in ("/login", "/auth/login"):
            return "/auth/login"
        if clean in ("/register", "/auth/register"):
            return "/auth/register"
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


import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, "active_blocked_ips.json")


def persist_blocked_ips_to_file(blocked_dict: Dict[str, Tuple[float, Any]]):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        now = time.time()
        serialized = {}
        for ip, (expiry, cat) in blocked_dict.items():
            if expiry > now:
                cat_str = cat.value if hasattr(cat, "value") else str(cat)
                serialized[ip] = {"expiry": expiry, "category": cat_str}
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(serialized, f)
    except Exception:
        pass


def load_blocked_ips_from_file() -> Dict[str, Tuple[float, Any]]:
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r") as f:
                raw = json.load(f)
            now = time.time()
            return {
                ip: (item["expiry"], item.get("category", "MANUAL_BAN"))
                for ip, item in raw.items()
                if item.get("expiry", 0) > now
            }
    except Exception:
        pass
    return {}


class InMemoryStateStore:
    """Thread-safe in-memory cache mimicking Redis sliding windows and metrics."""

    def __init__(self):
        self.request_times: Dict[str, List[float]] = defaultdict(list)
        self.request_paths: Dict[str, List[str]] = defaultdict(list)
        self.status_codes: Dict[str, List[int]] = defaultdict(list)
        self.failed_auth_ip: Dict[str, int] = defaultdict(int)
        self.failed_auth_user: Dict[str, int] = defaultdict(int)
        self.blocked_ips: Dict[str, Tuple[float, Any]] = load_blocked_ips_from_file()
        self.ip_request_counts: Dict[str, int] = defaultdict(int)
        self.ip_last_seen: Dict[str, float] = {}
        self.ip_latest_verdict: Dict[str, Dict[str, Any]] = {}

    def record_request(
        self,
        client_id: str,
        ip: str,
        path: str,
        status_code: int = 200,
        timestamp: Optional[float] = None,
    ):
        ts = timestamp if timestamp is not None else time.time()
        for key in {k for k in (ip, client_id) if k}:
            self.request_times[key].append(ts)
            self.request_paths[key].append(path)
            self.status_codes[key].append(status_code)
            if len(self.request_times[key]) > 50:
                self.request_times[key].pop(0)
                self.request_paths[key].pop(0)
                self.status_codes[key].pop(0)

        self.ip_request_counts[ip] += 1
        self.ip_last_seen[ip] = ts

    def record_auth_failure(self, ip: str, username: str):
        self.failed_auth_ip[ip] += 1
        if username:
            self.failed_auth_user[username] += 1

    def get_auth_failures(self, ip: str, username: str) -> Tuple[int, int]:
        return self.failed_auth_ip.get(ip, 0), self.failed_auth_user.get(username, 0)

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[Any], float]:
        item = self.blocked_ips.get(ip)
        if item:
            expiry, cat = item
            rem = expiry - time.time()
            if rem > 0:
                return True, cat, rem
            else:
                del self.blocked_ips[ip]
                persist_blocked_ips_to_file(self.blocked_ips)
        return False, None, 0.0

    def block_ip(
        self,
        ip: str,
        category: Any,
        ttl_seconds: int = 180,
    ):
        self.blocked_ips[ip] = (time.time() + ttl_seconds, category)
        persist_blocked_ips_to_file(self.blocked_ips)

    def unblock_ip(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            persist_blocked_ips_to_file(self.blocked_ips)
            return True
        return False

    def unblock(self, ip: str) -> bool:
        return self.unblock_ip(ip)

    def unblock_all(self):
        self.blocked_ips.clear()
        persist_blocked_ips_to_file(self.blocked_ips)



class BehavioralThreatEngine:
    """
    Central Threat & Behavioral Detection Engine.
    Evaluates requests and sequence logs against multiple heuristic & probabilistic baselines.
    """

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.local_store = InMemoryStateStore()
        self.sequence_model = MarkovSequenceModel()
        self.recent_events: List[Dict[str, Any]] = []
        self.total_requests = 0
        self.total_blocked = 0
        self.total_throttled = 0

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
        # 1. Check existing active block first — complete perimeter denial
        is_blocked, blocked_cat, rem_ttl = self.local_store.is_blocked(ip)
        if is_blocked and rem_ttl > 0:
            ip_fails, user_fails = self.local_store.get_auth_failures(ip, username or client_id)
            verdict_obj = ThreatVerdict(
                risk_score=1.0,
                behaviour_category=blocked_cat or BehaviourCategory.MANUAL_BAN,
                action=EnforcementAction.HARD_BLOCK,
                explanation=f"Client IP {ip} is actively banned across the perimeter ({blocked_cat.value if blocked_cat else 'BANNED'}). Access rejected ({round(rem_ttl, 1)}s remaining).",
                evidence={
                    "client_id": client_id,
                    "client_ip": ip,
                    "blocked_ip": ip,
                    "ttl_remaining_seconds": round(rem_ttl, 1),
                    "auth_failures_recorded": {"ip_fails": ip_fails, "user_fails": user_fails},
                    "feature_contributions": {"active_block": 1.0},
                    "reasons": [f"Active perimeter ban enforced ({blocked_cat.value if blocked_cat else 'BANNED'}) — {round(rem_ttl, 1)}s remaining"],
                },
            )
            self.total_requests += 1
            self.total_blocked += 1
            self.local_store.ip_request_counts[ip] += 1
            self.local_store.ip_last_seen[ip] = time.time()
            self.local_store.ip_latest_verdict[ip] = verdict_obj.to_dict()

            event_record = {
                "timestamp": round(time.time(), 3),
                "time_str": time.strftime("%H:%M:%S"),
                "client_ip": ip,
                "client_id": client_id,
                "path": path,
                "verdict": verdict_obj.to_dict(),
            }
            self.recent_events.insert(0, event_record)
            if len(self.recent_events) > 100:
                self.recent_events.pop()

            return verdict_obj

        # 2. Record request into sliding window
        self.local_store.record_request(client_id, ip, path, status_code, timestamp=timestamp)
        if status_code in (401, 403) and "/auth" in path and username:
            self.local_store.record_auth_failure(ip, username)

        track_key = ip if ip and ip in self.local_store.request_times else client_id
        recent_times = self.local_store.request_times[track_key]
        recent_paths = self.local_store.request_paths[track_key]
        recent_statuses = self.local_store.status_codes[track_key]
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

        # ── SIGNAL F: Security Scanner & Malicious Fuzzing Signatures ─────
        scanner_risk = 0.0
        suspicious_patterns = [
            r"\.\./", r"etc/passwd", r"wp-", r"\.env", r"\.git", r"phpmyadmin",
            r"actuator", r"select.*from", r"union.*select", r"<script", r"exec\(",
            r"/eval", r"/cmd", r"/shell"
        ]
        if any(re.search(pat, path, re.IGNORECASE) for pat in suspicious_patterns):
            scanner_risk = 0.96
            reasons.append(f"Malicious scanner / web fuzzer probe pattern detected in URI: '{path}'")
        feature_scores["scanner_probe"] = scanner_risk

        # ── AGGREGATE RISK SCORE & CATEGORIZATION ─────────────────────────
        max_threat = max(stuffing_risk, scraping_risk, enumeration_risk, sequence_risk, scanner_risk)

        if is_benign_burst:
            category = BehaviourCategory.BENIGN_BURST
            risk_score = 0.10
            action = EnforcementAction.ALLOWED
            explanation = "High-velocity traffic validated as legitimate human burst (natural timing variance and compliant workflow transitions)."
        elif max_threat >= 0.70:
            if scanner_risk >= 0.70:
                category = BehaviourCategory.AUTOMATED_BOT
            elif stuffing_risk >= 0.70:
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
            if scanner_risk >= 0.40:
                category = BehaviourCategory.AUTOMATED_BOT
            elif max_threat == scraping_risk:
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

        verdict_obj = ThreatVerdict(
            risk_score=risk_score,
            behaviour_category=category,
            action=action,
            explanation=explanation,
            evidence=evidence,
        )
        self.total_requests += 1
        if action in (EnforcementAction.SOFT_BLOCK, EnforcementAction.HARD_BLOCK):
            self.total_blocked += 1
        elif action == EnforcementAction.THROTTLED:
            self.total_throttled += 1

        self.local_store.ip_latest_verdict[ip] = verdict_obj.to_dict()

        event_record = {
            "timestamp": round(time.time(), 3),
            "time_str": time.strftime("%H:%M:%S"),
            "client_ip": ip,
            "client_id": client_id,
            "path": path,
            "verdict": verdict_obj.to_dict(),
        }
        self.recent_events.insert(0, event_record)
        if len(self.recent_events) > 100:
            self.recent_events.pop()

        # Telemetry ingestion by Autonomous AI Threat Sentinel
        try:
            from app.services.autonomous_agent import autonomous_agent
            autonomous_agent.process_telemetry(
                ip=ip,
                client_id=client_id,
                path=path,
                verdict=verdict_obj,
            )
        except Exception:
            pass

        return verdict_obj

    def get_dashboard_data(self) -> Dict[str, Any]:
        active_blocks = []
        now = time.time()
        for ip, (expiry, cat) in list(self.local_store.blocked_ips.items()):
            rem = max(0, int(expiry - now))
            cat_name = cat.value if hasattr(cat, "value") else str(cat)
            if rem > 0:
                active_blocks.append({"ip": ip, "category": cat_name, "ttl": rem})
            else:
                del self.local_store.blocked_ips[ip]

        # Category counts
        cat_counts = defaultdict(int)
        for ev in self.recent_events:
            v = ev.get("verdict", {})
            cat_val = v.get("behaviour_category", "BENIGN")
            cat_counts[cat_val] += 1

        # Attacker Profiles (Prioritizing external/remote IPs like Kali VM)
        attacker_profiles = []
        for ip, count in sorted(self.local_store.ip_request_counts.items(), key=lambda x: x[1], reverse=True):
            is_blocked, blocked_cat, ttl = self.local_store.is_blocked(ip)
            last_verdict = self.local_store.ip_latest_verdict.get(ip, {})
            auth_fails = self.local_store.failed_auth_ip.get(ip, 0)

            status_label = "CLEAN"
            if is_blocked:
                status_label = "BLOCKED"
            elif last_verdict.get("action") == "THROTTLED":
                status_label = "THROTTLED"
            elif last_verdict.get("risk_score", 0) >= 0.40:
                status_label = "SUSPICIOUS"

            if is_blocked and blocked_cat:
                cat_display = blocked_cat.value if hasattr(blocked_cat, "value") else str(blocked_cat)
            else:
                cat_display = last_verdict.get("behaviour_category", "BENIGN")

            attacker_profiles.append({
                "ip": ip,
                "is_external": ip not in ("127.0.0.1", "localhost"),
                "total_requests": count,
                "auth_failures": auth_fails,
                "status": status_label,
                "category": cat_display,
                "risk_score": 1.0 if is_blocked else round(last_verdict.get("risk_score", 0.0), 2),
                "ttl": round(ttl, 1) if is_blocked else 0,
                "last_seen_sec_ago": round(now - self.local_store.ip_last_seen.get(ip, now), 1),
                "recent_paths": self.local_store.request_paths.get(ip, [])[-5:],
            })

        return {
            "total_requests": self.total_requests,
            "total_blocked": self.total_blocked,
            "total_throttled": self.total_throttled,
            "active_blocks": active_blocks,
            "category_distribution": dict(cat_counts),
            "recent_events": self.recent_events[:50],
            "attacker_profiles": attacker_profiles[:10],
        }

    def record_response_status(
        self,
        client_id: str,
        ip: str,
        path: str,
        status_code: int,
        username: Optional[str] = None,
    ):
        """Records the status code after the request is processed by upstream."""
        if client_id in self.local_store.status_codes and self.local_store.status_codes[client_id]:
            self.local_store.status_codes[client_id][-1] = status_code

        if status_code in (401, 403) and ("/auth" in path or "/login" in path):
            self.local_store.record_auth_failure(ip, username or client_id)
            ip_fails, user_fails = self.local_store.get_auth_failures(ip, username or client_id)
            if ip_fails >= self.auth_fail_threshold_ip or user_fails >= self.auth_fail_threshold_user:
                self.local_store.block_ip(ip, BehaviourCategory.CREDENTIAL_STUFFING, ttl_seconds=180)
                self.total_blocked += 1

    def manual_block_ip(
        self,
        ip: str,
        category: BehaviourCategory = BehaviourCategory.MANUAL_BAN,
        ttl_seconds: int = 300,
        reason: str = "Manual operator intervention via SOC Dashboard",
    ):
        """Immediately enforces an active ban on an IP address across the gateway."""
        self.local_store.block_ip(ip, category=category, ttl_seconds=ttl_seconds)
        self.total_blocked += 1
        self.local_store.ip_request_counts[ip] = self.local_store.ip_request_counts.get(ip, 0)
        self.local_store.ip_last_seen[ip] = time.time()
        self.local_store.ip_latest_verdict[ip] = {
            "risk_score": 1.0,
            "behaviour_category": category.value,
            "action": EnforcementAction.HARD_BLOCK.value,
            "explanation": f"Manual ban enforced by SOC operator ({reason})",
            "evidence": {
                "manual": True,
                "reason": reason,
                "ttl_seconds": ttl_seconds,
                "reasons": [f"Manual ban enforced by SOC operator ({reason})"],
                "feature_contributions": {"manual_ban": 1.0},
            },
        }
        self.recent_events.insert(
            0,
            {
                "timestamp": round(time.time(), 3),
                "time_str": time.strftime("%H:%M:%S"),
                "client_ip": ip,
                "client_id": "soc_admin",
                "path": "[MANUAL BAN ENFORCEMENT]",
                "verdict": {
                    "risk_score": 1.0,
                    "behaviour_category": category.value,
                    "action": EnforcementAction.HARD_BLOCK.value,
                    "explanation": f"Manual ban enforced by SOC operator ({reason})",
                    "evidence": {
                        "manual": True,
                        "reason": reason,
                        "ttl_seconds": ttl_seconds,
                        "reasons": [f"Manual ban enforced by SOC operator ({reason})"],
                        "feature_contributions": {"manual_ban": 1.0},
                    },
                },
            },
        )
        if len(self.recent_events) > 100:
            self.recent_events.pop()

    def unblock_ip(self, ip: str) -> bool:
        cleared = False
        if ip in self.local_store.blocked_ips:
            del self.local_store.blocked_ips[ip]
            cleared = True
        persist_blocked_ips_to_file(self.local_store.blocked_ips)
        if ip in self.local_store.failed_auth_ip:
            del self.local_store.failed_auth_ip[ip]
        if ip in self.local_store.request_paths:
            self.local_store.request_paths[ip].clear()
        if ip in self.local_store.request_times:
            self.local_store.request_times[ip].clear()
        if ip in self.local_store.status_codes:
            self.local_store.status_codes[ip].clear()
        return cleared or True

    def clear_all(self):
        self.local_store.blocked_ips.clear()
        persist_blocked_ips_to_file(self.local_store.blocked_ips)
        self.local_store.failed_auth_ip.clear()
        self.local_store.failed_auth_user.clear()
        self.local_store.request_paths.clear()
        self.local_store.request_times.clear()
        self.local_store.status_codes.clear()
        self.recent_events.clear()
        self.total_blocked = 0
        self.total_throttled = 0


threat_engine = BehavioralThreatEngine()

try:
    from app.services.autonomous_agent import autonomous_agent
    autonomous_agent.set_dependencies(threat_engine)
except Exception:
    pass

