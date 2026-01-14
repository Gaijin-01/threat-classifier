"""
Test examples for Threat Classifier API
Run: python test_examples.py
"""

import httpx
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_wallet_drainer():
    """Test wallet drainer detection"""
    event = {
        "event_type": "wallet_interaction",
        "source_ip": "45.33.32.156",
        "source_wallet": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE21",
        "payload": {
            "method": "setApprovalForAll",
            "operator": "0xDEADBEEF",
            "approved": True,
            "amount": 115792089237316195423570985008687907853269984665640564039457584007913129639935
        },
        "context": {}
    }
    
    response = httpx.post(f"{BASE_URL}/classify", json=event)
    result = response.json()
    
    print("🚨 Wallet Drainer Test:")
    print(f"   Threat: {result['threat_type']}")
    print(f"   Severity: {result['severity']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Action: {result['recommended_action']}")
    print(f"   Reasoning: {result['reasoning']}")
    print(f"   Indicators: {result['indicators']}")
    print()

def test_brute_force_login():
    """Test brute force login detection"""
    event = {
        "event_type": "login",
        "source_ip": "203.0.113.42",
        "user_id": "user_12345",
        "payload": {
            "username": "admin@example.com",
            "success": False
        },
        "context": {
            "failed_attempts": 15,
            "new_device": True,
            "new_location": True,
            "country": "KP"
        }
    }
    
    response = httpx.post(f"{BASE_URL}/classify", json=event)
    result = response.json()
    
    print("🔐 Brute Force Login Test:")
    print(f"   Threat: {result['threat_type']}")
    print(f"   Severity: {result['severity']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Action: {result['recommended_action']}")
    print(f"   Reasoning: {result['reasoning']}")
    print()

def test_suspicious_withdrawal():
    """Test suspicious withdrawal detection"""
    event = {
        "event_type": "transaction",
        "source_ip": "198.51.100.23",
        "source_wallet": "0x123abc",
        "api_key_hash": "key_hash_abc123",
        "payload": {
            "type": "withdrawal",
            "amount": 50000,
            "currency": "USDC",
            "to_address": "0xNEWADDRESS123"
        },
        "context": {
            "usual_max_amount": 1000,
            "is_new_address": True,
            "withdrawals_last_hour": 8
        }
    }
    
    response = httpx.post(f"{BASE_URL}/classify", json=event)
    result = response.json()
    
    print("💸 Suspicious Withdrawal Test:")
    print(f"   Threat: {result['threat_type']}")
    print(f"   Severity: {result['severity']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Action: {result['recommended_action']}")
    print(f"   Indicators: {result['indicators']}")
    print()

def test_clean_event():
    """Test normal/clean event"""
    event = {
        "event_type": "api_call",
        "source_ip": "8.8.8.8",
        "api_key_hash": "valid_key_hash",
        "endpoint": "/api/v1/balance",
        "payload": {"account_id": "12345"},
        "context": {}
    }
    
    response = httpx.post(f"{BASE_URL}/classify", json=event)
    result = response.json()
    
    print("✅ Clean Event Test:")
    print(f"   Threat: {result['threat_type']}")
    print(f"   Severity: {result['severity']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Action: {result['recommended_action']}")
    print()

def test_malicious_ip():
    """Test malicious IP detection"""
    event = {
        "event_type": "api_call",
        "source_ip": "185.220.101.42",  # Tor exit pattern
        "endpoint": "/api/v1/withdraw",
        "payload": {}
    }
    
    response = httpx.post(f"{BASE_URL}/classify", json=event)
    result = response.json()
    
    print("🌐 Malicious IP Test:")
    print(f"   Threat: {result['threat_type']}")
    print(f"   Severity: {result['severity']}")
    print(f"   Action: {result['recommended_action']}")
    print(f"   Indicators: {result['indicators']}")
    print()

def test_batch_classification():
    """Test batch classification"""
    events = [
        {"event_type": "api_call", "source_ip": "1.2.3.4", "endpoint": "/balance", "payload": {}},
        {"event_type": "login", "source_ip": "5.6.7.8", "context": {"failed_attempts": 20}, "payload": {}},
        {"event_type": "wallet_interaction", "payload": {"method": "setApprovalForAll"}}
    ]
    
    response = httpx.post(f"{BASE_URL}/classify/batch", json=events)
    results = response.json()
    
    print("📦 Batch Classification Test:")
    for i, result in enumerate(results):
        print(f"   Event {i+1}: {result['threat_type']} ({result['severity']})")
    print()

if __name__ == "__main__":
    print("=" * 50)
    print("Threat Classifier API - Test Suite")
    print("=" * 50)
    print()
    
    # Check health
    try:
        health = httpx.get(f"{BASE_URL}/health").json()
        print(f"✓ API is healthy: v{health['version']}")
        print()
    except Exception as e:
        print(f"✗ API not reachable: {e}")
        print("  Make sure to run: uvicorn main:app --reload")
        exit(1)
    
    test_wallet_drainer()
    test_brute_force_login()
    test_suspicious_withdrawal()
    test_clean_event()
    test_malicious_ip()
    test_batch_classification()
    
    print("=" * 50)
    print("All tests completed!")
