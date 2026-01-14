"""
Threat Classification API v0.2
Features: SQLite logging, AbuseIPDB, Webhooks, Dashboard
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timedelta
from enum import Enum
from contextlib import asynccontextmanager
import hashlib
import json
import re
import os
import httpx
import sqlite3
import asyncio

# ============== Database Setup ==============

DB_PATH = os.getenv("DB_PATH", "/tmp/threats.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        event_type TEXT,
        source_ip TEXT,
        source_wallet TEXT,
        threat_type TEXT,
        severity TEXT,
        confidence REAL,
        reasoning TEXT,
        action TEXT,
        indicators TEXT,
        raw_event TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS ip_cache (
        ip TEXT PRIMARY KEY,
        abuse_score INTEGER,
        is_tor INTEGER,
        country TEXT,
        checked_at TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_threat ON events(threat_type)')
    conn.commit()
    conn.close()

def save_event(result, event):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', (
            result.event_id,
            result.timestamp.isoformat(),
            event.event_type.value,
            event.source_ip,
            event.source_wallet,
            result.threat_type.value,
            result.severity.value,
            result.confidence,
            result.reasoning,
            result.recommended_action.value,
            json.dumps(result.indicators),
            json.dumps(event.payload)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB save error: {e}")

def get_stats(hours=24):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        c.execute('SELECT COUNT(*) FROM events WHERE timestamp > ?', (since,))
        total = c.fetchone()[0]
        
        c.execute('SELECT severity, COUNT(*) FROM events WHERE timestamp > ? GROUP BY severity', (since,))
        by_severity = dict(c.fetchall())
        
        c.execute('SELECT threat_type, COUNT(*) FROM events WHERE timestamp > ? GROUP BY threat_type', (since,))
        by_threat = dict(c.fetchall())
        
        c.execute('SELECT source_ip, COUNT(*) as cnt FROM events WHERE timestamp > ? AND source_ip IS NOT NULL GROUP BY source_ip ORDER BY cnt DESC LIMIT 10', (since,))
        top_ips = c.fetchall()
        
        conn.close()
        return {"total": total, "by_severity": by_severity, "by_threat": by_threat, "top_ips": top_ips}
    except:
        return {"total": 0, "by_severity": {}, "by_threat": {}, "top_ips": []}

# ============== Lifespan ==============

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Threat Classifier API",
    description="AI-driven security event classification for crypto/trading",
    version="0.2.0",
    lifespan=lifespan
)

# ============== Models ==============

class EventType(str, Enum):
    API_CALL = "api_call"
    TRANSACTION = "transaction"
    LOGIN = "login"
    WALLET_INTERACTION = "wallet_interaction"
    SMART_CONTRACT = "smart_contract"
    WEBHOOK = "webhook"
    RATE_LIMIT = "rate_limit"

class ThreatType(str, Enum):
    CREDENTIAL_THEFT = "credential_theft"
    BRUTE_FORCE = "brute_force"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    WALLET_DRAINER = "wallet_drainer"
    API_ABUSE = "api_abuse"
    PHISHING = "phishing"
    SUSPICIOUS_WITHDRAWAL = "suspicious_withdrawal"
    IP_ANOMALY = "ip_anomaly"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"
    KNOWN_ATTACKER = "known_attacker"
    TOR_EXIT = "tor_exit"
    CLEAN = "clean"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RecommendedAction(str, Enum):
    BLOCK = "block"
    ALERT = "alert"
    MONITOR = "monitor"
    IGNORE = "ignore"
    QUARANTINE_WALLET = "quarantine_wallet"
    REVOKE_API_KEY = "revoke_api_key"
    REQUIRE_2FA = "require_2fa"

class SecurityEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: EventType
    source_ip: Optional[str] = None
    source_wallet: Optional[str] = None
    api_key_hash: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    payload: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)

class ClassificationResult(BaseModel):
    event_id: str
    timestamp: datetime
    threat_type: ThreatType
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    reasoning: str
    recommended_action: RecommendedAction
    indicators: list[str]
    metadata: dict = Field(default_factory=dict)

class WebhookEvent(BaseModel):
    source: str
    event_type: str
    data: dict

# ============== AbuseIPDB Integration ==============

class AbuseIPDB:
    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_KEY")
        self.enabled = bool(self.api_key)
    
    async def check_ip(self, ip: str) -> dict:
        if not self.enabled or not ip:
            return {"score": 0, "is_tor": False, "country": None}
        
        # Check cache first
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT abuse_score, is_tor, country, checked_at FROM ip_cache WHERE ip = ?', (ip,))
            row = c.fetchone()
            if row:
                checked = datetime.fromisoformat(row[3])
                if datetime.utcnow() - checked < timedelta(hours=24):
                    conn.close()
                    return {"score": row[0], "is_tor": bool(row[1]), "country": row[2]}
            conn.close()
        except:
            pass
        
        # Query API
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    timeout=5
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result = {
                        "score": data.get("abuseConfidenceScore", 0),
                        "is_tor": data.get("isTor", False),
                        "country": data.get("countryCode")
                    }
                    # Cache result
                    try:
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute('INSERT OR REPLACE INTO ip_cache VALUES (?,?,?,?,?)',
                            (ip, result["score"], int(result["is_tor"]), result["country"], datetime.utcnow().isoformat()))
                        conn.commit()
                        conn.close()
                    except:
                        pass
                    return result
        except:
            pass
        return {"score": 0, "is_tor": False, "country": None}

abuse_ipdb = AbuseIPDB()

# ============== Rule Engine ==============

class ThreatRuleEngine:
    SUSPICIOUS_ENDPOINTS = [r".*withdraw.*", r".*transfer.*", r".*export.*key.*", r".*admin.*", r".*debug.*"]
    KNOWN_MALICIOUS_IPS = {"192.168.1.100"}
    HIGH_RISK_COUNTRIES = {"KP", "IR"}
    DRAINER_SIGNATURES = ["setApprovalForAll", "approve(address,uint256)", "transferFrom", "unlimited_allowance", "permit2"]
    
    def __init__(self):
        self.event_history: dict[str, list] = {}
    
    def _generate_event_id(self, event: SecurityEvent) -> str:
        data = f"{event.timestamp}{event.event_type}{event.source_ip}{event.payload}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _check_rate_anomaly(self, event: SecurityEvent) -> tuple[bool, int]:
        key = event.source_ip or event.api_key_hash or event.user_id
        if not key:
            return False, 0
        now = datetime.utcnow()
        if key not in self.event_history:
            self.event_history[key] = []
        self.event_history[key] = [ts for ts in self.event_history[key] if (now - ts).seconds < 300]
        self.event_history[key].append(now)
        count = len(self.event_history[key])
        return count > 50, count
    
    def _check_endpoint_risk(self, endpoint: str) -> tuple[bool, str]:
        if not endpoint:
            return False, ""
        for pattern in self.SUSPICIOUS_ENDPOINTS:
            if re.match(pattern, endpoint.lower()):
                return True, pattern
        return False, ""
    
    def _check_wallet_drainer(self, payload: dict) -> tuple[bool, list[str]]:
        indicators = []
        payload_str = json.dumps(payload).lower()
        for sig in self.DRAINER_SIGNATURES:
            if sig.lower() in payload_str:
                indicators.append(f"Drainer signature: {sig}")
        if "amount" in payload:
            amount = payload.get("amount", 0)
            if isinstance(amount, (int, float)) and amount > 1e18:
                indicators.append("Unlimited approval amount")
        return len(indicators) > 0, indicators
    
    def _check_login_anomaly(self, event: SecurityEvent) -> tuple[bool, list[str]]:
        indicators = []
        ctx = event.context
        if ctx.get("failed_attempts", 0) > 5:
            indicators.append(f"Failed attempts: {ctx['failed_attempts']}")
        if ctx.get("new_device") and ctx.get("new_location"):
            indicators.append("New device + new location")
        if ctx.get("country") in self.HIGH_RISK_COUNTRIES:
            indicators.append(f"High-risk country: {ctx['country']}")
        return len(indicators) > 0, indicators
    
    def _check_transaction_anomaly(self, event: SecurityEvent) -> tuple[bool, list[str]]:
        indicators = []
        payload, ctx = event.payload, event.context
        amount = payload.get("amount", 0)
        usual_max = ctx.get("usual_max_amount", float("inf"))
        if amount > usual_max * 3:
            indicators.append(f"Amount {amount} > 3x usual max")
        if payload.get("to_address") and ctx.get("is_new_address"):
            indicators.append("New withdrawal address")
        if ctx.get("withdrawals_last_hour", 0) > 5:
            indicators.append("Multiple withdrawals/hour")
        return len(indicators) > 0, indicators

    async def classify(self, event: SecurityEvent) -> ClassificationResult:
        event_id = self._generate_event_id(event)
        indicators = []
        threat_type = ThreatType.CLEAN
        severity = Severity.INFO
        confidence = 0.5
        action = RecommendedAction.IGNORE
        reasoning_parts = []
        
        # AbuseIPDB check
        if event.source_ip:
            ip_info = await abuse_ipdb.check_ip(event.source_ip)
            if ip_info["score"] >= 80:
                indicators.append(f"AbuseIPDB score: {ip_info['score']}")
                threat_type = ThreatType.KNOWN_ATTACKER
                severity = Severity.CRITICAL
                confidence = 0.95
                action = RecommendedAction.BLOCK
                reasoning_parts.append(f"Known malicious IP (score {ip_info['score']})")
            elif ip_info["is_tor"]:
                indicators.append("Tor exit node")
                threat_type = ThreatType.TOR_EXIT
                severity = Severity.HIGH
                confidence = 0.9
                action = RecommendedAction.BLOCK
                reasoning_parts.append("Tor exit node detected")
            elif ip_info["country"] in self.HIGH_RISK_COUNTRIES:
                indicators.append(f"High-risk country: {ip_info['country']}")
                if threat_type == ThreatType.CLEAN:
                    threat_type = ThreatType.IP_ANOMALY
                    severity = Severity.MEDIUM
                    confidence = 0.7
                    action = RecommendedAction.ALERT
                reasoning_parts.append(f"High-risk country: {ip_info['country']}")
        
        # Rate check
        rate_anomaly, rate_count = self._check_rate_anomaly(event)
        if rate_anomaly:
            indicators.append(f"Rate: {rate_count}/5min")
            if severity.value not in ["critical", "high"]:
                threat_type = ThreatType.RATE_LIMIT_ABUSE
                severity = Severity.MEDIUM
                confidence = 0.8
                action = RecommendedAction.ALERT
            reasoning_parts.append("Rate anomaly")
        
        # Endpoint check
        if event.endpoint:
            risky, pattern = self._check_endpoint_risk(event.endpoint)
            if risky:
                indicators.append(f"Endpoint: {pattern}")
                if threat_type == ThreatType.CLEAN:
                    threat_type = ThreatType.ANOMALOUS_BEHAVIOR
                    severity = Severity.MEDIUM
                    confidence = 0.7
                    action = RecommendedAction.MONITOR
                reasoning_parts.append("Sensitive endpoint")
        
        # Type-specific checks
        if event.event_type == EventType.WALLET_INTERACTION:
            is_drainer, d_ind = self._check_wallet_drainer(event.payload)
            if is_drainer:
                indicators.extend(d_ind)
                threat_type = ThreatType.WALLET_DRAINER
                severity = Severity.CRITICAL
                confidence = 0.95
                action = RecommendedAction.BLOCK
                reasoning_parts.append("Wallet drainer detected")
        
        elif event.event_type == EventType.LOGIN:
            sus, l_ind = self._check_login_anomaly(event)
            if sus:
                indicators.extend(l_ind)
                threat_type = ThreatType.BRUTE_FORCE if "Failed" in str(l_ind) else ThreatType.ANOMALOUS_BEHAVIOR
                severity = Severity.HIGH
                confidence = 0.85
                action = RecommendedAction.REQUIRE_2FA
                reasoning_parts.append("Login anomaly")
        
        elif event.event_type == EventType.TRANSACTION:
            sus, t_ind = self._check_transaction_anomaly(event)
            if sus:
                indicators.extend(t_ind)
                threat_type = ThreatType.SUSPICIOUS_WITHDRAWAL
                severity = Severity.HIGH
                confidence = 0.8
                action = RecommendedAction.ALERT
                reasoning_parts.append("Transaction anomaly")
        
        reasoning = " | ".join(reasoning_parts) if reasoning_parts else "No threats detected"
        
        return ClassificationResult(
            event_id=event_id, timestamp=datetime.utcnow(), threat_type=threat_type,
            severity=severity, confidence=confidence, reasoning=reasoning,
            recommended_action=action, indicators=indicators,
            metadata={"engine": "0.2.0", "method": "rule_based", "abuseipdb": abuse_ipdb.enabled}
        )

# ============== Telegram ==============

class TelegramAlerter:
    def __init__(self):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.enabled = bool(self.token and self.chat_id)
    
    async def send_alert(self, result: ClassificationResult):
        if not self.enabled or result.severity == Severity.INFO:
            return
        emoji = {"critical": "🚨🚨🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}
        ind_text = "\n".join(f"• {i}" for i in result.indicators) or "None"
        msg = f"""{emoji.get(result.severity.value, "⚠️")} THREAT DETECTED

Type: {result.threat_type.value}
Severity: {result.severity.value.upper()}
Confidence: {result.confidence:.0%}

{result.reasoning}

Action: {result.recommended_action.value}

Indicators:
{ind_text}

ID: {result.event_id}"""
        try:
            async with httpx.AsyncClient() as client:
                await client.post(f"https://api.telegram.org/bot{self.token}/sendMessage",
                    json={"chat_id": self.chat_id, "text": msg}, timeout=10)
        except:
            pass

engine = ThreatRuleEngine()
alerter = TelegramAlerter()

# ============== Routes ==============

@app.get("/")
async def root():
    return {"name": "Threat Classifier API", "version": "0.2.0", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "0.2.0", "telegram": alerter.enabled, "abuseipdb": abuse_ipdb.enabled}

@app.post("/classify", response_model=ClassificationResult)
async def classify_event(event: SecurityEvent, background: BackgroundTasks):
    result = await engine.classify(event)
    background.add_task(save_event, result, event)
    background.add_task(alerter.send_alert, result)
    return result

@app.post("/classify/batch", response_model=list[ClassificationResult])
async def classify_batch(events: list[SecurityEvent], background: BackgroundTasks):
    results = []
    for event in events:
        result = await engine.classify(event)
        background.add_task(save_event, result, event)
        background.add_task(alerter.send_alert, result)
        results.append(result)
    return results

@app.post("/webhook/{source}")
async def receive_webhook(source: str, data: dict, background: BackgroundTasks, x_api_key: Optional[str] = Header(None)):
    api_key = os.getenv("WEBHOOK_API_KEY")
    if api_key and x_api_key != api_key:
        raise HTTPException(401, "Invalid API key")
    
    event_type = EventType.WEBHOOK
    if "login" in str(data).lower():
        event_type = EventType.LOGIN
    elif "transaction" in str(data).lower() or "transfer" in str(data).lower():
        event_type = EventType.TRANSACTION
    elif "wallet" in str(data).lower() or "approve" in str(data).lower():
        event_type = EventType.WALLET_INTERACTION
    
    event = SecurityEvent(
        event_type=event_type,
        source_ip=data.get("ip") or data.get("source_ip"),
        source_wallet=data.get("wallet") or data.get("address"),
        payload=data,
        context={"source": source}
    )
    result = await engine.classify(event)
    background.add_task(save_event, result, event)
    background.add_task(alerter.send_alert, result)
    return {"received": True, "event_id": result.event_id, "threat": result.threat_type.value, "severity": result.severity.value}

@app.get("/dashboard")
async def dashboard(hours: int = 24):
    stats = get_stats(hours)
    return {
        "period_hours": hours,
        "total_events": stats["total"],
        "by_severity": stats["by_severity"],
        "by_threat_type": stats["by_threat"],
        "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in stats["top_ips"]]
    }

@app.get("/threats")
async def list_threats():
    return {"threat_types": [t.value for t in ThreatType], "severities": [s.value for s in Severity], "actions": [a.value for a in RecommendedAction]}

@app.post("/test-alert")
async def test_alert():
    r = ClassificationResult(
        event_id="test_123", timestamp=datetime.utcnow(), threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
        severity=Severity.MEDIUM, confidence=0.85, reasoning="Test alert",
        recommended_action=RecommendedAction.MONITOR, indicators=["Test 1", "Test 2"], metadata={"test": True}
    )
    await alerter.send_alert(r)
    return {"status": "sent", "telegram": alerter.enabled}

if __name__ == "__main__":
    import uvicorn
    uvicor
