"""
Threat Classification API - MVP
Crypto/Trading Security Focus
Zero-cost rule-based engine with Telegram alerts
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import os
import httpx

app = FastAPI(
    title="Threat Classifier API",
    description="AI-driven security event classification for crypto/trading infrastructure",
    version="0.1.0"
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

# ============== Rule Engine ==============

class ThreatRuleEngine:
    SUSPICIOUS_ENDPOINTS = [
        r".*withdraw.*",
        r".*transfer.*",
        r".*export.*key.*",
        r".*admin.*",
        r".*debug.*",
    ]
    
    KNOWN_MALICIOUS_IPS = {"192.168.1.100"}
    HIGH_RISK_COUNTRIES = {"KP", "IR", "RU"}
    
    DRAINER_SIGNATURES = [
        "setApprovalForAll",
        "approve(address,uint256)",
        "transferFrom",
        "unlimited_allowance",
    ]
    
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
        
        self.event_history[key] = [
            ts for ts in self.event_history[key]
            if (now - ts).seconds < 300
        ]
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
                indicators.append("Unlimited approval amount detected")
        
        return len(indicators) > 0, indicators
    
    def _check_ip_reputation(self, ip: str) -> tuple[bool, str]:
        if ip in self.KNOWN_MALICIOUS_IPS:
            return True, "Known malicious IP"
        
        if ip.startswith("185.220.") or ip.startswith("23.129."):
            return True, "Possible Tor exit node"
        
        return False, ""
    
    def _check_login_anomaly(self, event: SecurityEvent) -> tuple[bool, list[str]]:
        indicators = []
        ctx = event.context
        
        if ctx.get("failed_attempts", 0) > 5:
            indicators.append(f"Multiple failed attempts: {ctx['failed_attempts']}")
        
        if ctx.get("new_device", False) and ctx.get("new_location", False):
            indicators.append("New device from new location")
        
        if ctx.get("country") in self.HIGH_RISK_COUNTRIES:
            indicators.append(f"High-risk country: {ctx['country']}")
        
        return len(indicators) > 0, indicators
    
    def _check_transaction_anomaly(self, event: SecurityEvent) -> tuple[bool, list[str]]:
        indicators = []
        payload = event.payload
        ctx = event.context
        
        amount = payload.get("amount", 0)
        usual_max = ctx.get("usual_max_amount", float("inf"))
        if amount > usual_max * 3:
            indicators.append(f"Amount {amount} exceeds 3x usual maximum")
        
        if payload.get("to_address") and ctx.get("is_new_address", False):
            indicators.append("Withdrawal to previously unseen address")
        
        if ctx.get("withdrawals_last_hour", 0) > 5:
            indicators.append("Multiple withdrawals in short timeframe")
        
        return len(indicators) > 0, indicators

    def classify(self, event: SecurityEvent) -> ClassificationResult:
        event_id = self._generate_event_id(event)
        indicators = []
        threat_type = ThreatType.CLEAN
        severity = Severity.INFO
        confidence = 0.5
        action = RecommendedAction.IGNORE
        reasoning_parts = []
        
        rate_anomaly, rate_count = self._check_rate_anomaly(event)
        if rate_anomaly:
            indicators.append(f"Rate anomaly: {rate_count} requests in 5 min")
            threat_type = ThreatType.RATE_LIMIT_ABUSE
            severity = Severity.MEDIUM
            confidence = 0.8
            action = RecommendedAction.ALERT
            reasoning_parts.append("Unusual request rate detected")
        
        if event.source_ip:
            ip_malicious, ip_reason = self._check_ip_reputation(event.source_ip)
            if ip_malicious:
                indicators.append(ip_reason)
                threat_type = ThreatType.IP_ANOMALY
                severity = Severity.HIGH
                confidence = 0.9
                action = RecommendedAction.BLOCK
                reasoning_parts.append(f"Suspicious source: {ip_reason}")
        
        if event.endpoint:
            endpoint_risky, pattern = self._check_endpoint_risk(event.endpoint)
            if endpoint_risky:
                indicators.append(f"Suspicious endpoint pattern: {pattern}")
                if threat_type == ThreatType.CLEAN:
                    threat_type = ThreatType.ANOMALOUS_BEHAVIOR
                    severity = Severity.MEDIUM
                    confidence = 0.7
                    action = RecommendedAction.MONITOR
                reasoning_parts.append("Accessing sensitive endpoint")
        
        if event.event_type == EventType.WALLET_INTERACTION:
            is_drainer, drainer_indicators = self._check_wallet_drainer(event.payload)
            if is_drainer:
                indicators.extend(drainer_indicators)
                threat_type = ThreatType.WALLET_DRAINER
                severity = Severity.CRITICAL
                confidence = 0.95
                action = RecommendedAction.BLOCK
                reasoning_parts.append("Wallet drainer pattern detected")
        
        elif event.event_type == EventType.LOGIN:
            is_suspicious, login_indicators = self._check_login_anomaly(event)
            if is_suspicious:
                indicators.extend(login_indicators)
                threat_type = ThreatType.BRUTE_FORCE if "failed" in str(login_indicators) else ThreatType.ANOMALOUS_BEHAVIOR
                severity = Severity.HIGH
                confidence = 0.85
                action = RecommendedAction.REQUIRE_2FA
                reasoning_parts.append("Suspicious login pattern")
        
        elif event.event_type == EventType.TRANSACTION:
            is_suspicious, tx_indicators = self._check_transaction_anomaly(event)
            if is_suspicious:
                indicators.extend(tx_indicators)
                threat_type = ThreatType.SUSPICIOUS_WITHDRAWAL
                severity = Severity.HIGH
                confidence = 0.8
                action = RecommendedAction.ALERT
                reasoning_parts.append("Transaction anomaly detected")
        
        if not reasoning_parts:
            reasoning = "No threats detected. Event appears normal."
        else:
            reasoning = " | ".join(reasoning_parts)
        
        return ClassificationResult(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning,
            recommended_action=action,
            indicators=indicators,
            metadata={
                "engine_version": "0.1.0",
                "classification_method": "rule_based"
            }
        )

# ============== Telegram Alert ==============

class TelegramAlerter:
    def __init__(self):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.enabled = bool(self.token and self.chat_id)
    
    async def send_alert(self, result: ClassificationResult):
        if not self.enabled:
            return
        
        if result.severity == Severity.INFO:
            return
        
        emoji = {
            Severity.CRITICAL: "🚨🚨🚨",
            Severity.HIGH: "🔴",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "ℹ️"
        }
        
        indicators_text = "\n".join(f"• {ind}" for ind in result.indicators) if result.indicators else "None"
        
        message = f"""{emoji.get(result.severity, "⚠️")} THREAT DETECTED

Type: {result.threat_type.value}
Severity: {result.severity.value.upper()}
Confidence: {result.confidence:.0%}

Reasoning: {result.reasoning}

Recommended Action: {result.recommended_action.value}

Indicators:
{indicators_text}

Event ID: {result.event_id}
Time: {result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}"""
        
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"https://api.telegram.org/bot{self.token}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": message
                    },
                    timeout=10
                )
        except Exception as e:
            print(f"Telegram alert failed: {e}")

# ============== API Routes ==============

engine = ThreatRuleEngine()
alerter = TelegramAlerter()

@app.get("/")
async def root():
    return {
        "name": "Threat Classifier API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "0.1.0",
        "telegram_enabled": alerter.enabled
    }

@app.post("/classify", response_model=ClassificationResult)
async def classify_event(event: SecurityEvent):
    try:
        result = engine.classify(event)
        await alerter.send_alert(result)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/classify/batch", response_model=list[ClassificationResult])
async def classify_batch(events: list[SecurityEvent]):
    results = []
    for event in events:
        result = engine.classify(event)
        await alerter.send_alert(result)
        results.append(result)
    return results

@app.get("/threats")
async def list_threat_types():
    return {
        "threat_types": [t.value for t in ThreatType],
        "severities": [s.value for s in Severity],
        "actions": [a.value for a in RecommendedAction]
    }

@app.post("/test-alert")
async def test_alert():
    test_result = ClassificationResult(
        event_id="test_123",
        timestamp=datetime.utcnow(),
        threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence=0.85,
        reasoning="This is a test alert to verify Telegram integration",
        recommended_action=RecommendedAction.MONITOR,
        indicators=["Test indicator 1", "Test indicator 2"],
        metadata={"test": True}
    )
    await alerter.send_alert(test_result)
    return {"status": "Test alert sent", "telegram_enabled": alerter.enabled}

# ============== Run ==============

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
