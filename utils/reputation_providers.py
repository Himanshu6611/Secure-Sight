# utils/reputation_providers.py
"""
utils/reputation_providers.py
------------------------------
Reputation Provider Abstraction Layer & Aggregator Engine for SecureSight Phase 3.
Provides standardized ReputationProvider interface, LocalBlacklistProvider, ExternalAPIProvider skeletons,
MockReputationProvider for testing, and MultiProviderAggregator for evidence provenance.
"""

import os
import datetime
from abc import ABC, abstractmethod
from typing import Dict, List, Any
import requests

from utils.reputation import BLACKLIST


class ReputationProvider(ABC):
    """Abstract Base Class for Reputation Providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name identifier of reputation provider."""
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform reputation lookup for a normalized domain name.

        Returns normalized response:
            {
                "provider": str,
                "status": str (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN, UNAVAILABLE, ERROR),
                "confidence": float (0.0 - 1.0),
                "checked_at": str (ISO timestamp),
                "details": str
            }
        """
        pass


class LocalBlacklistProvider(ReputationProvider):
    """Provider backed by local threat intelligence CSV blacklist."""

    @property
    def name(self) -> str:
        return "local_blacklist"

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        if not domain:
            return {
                "provider": self.name,
                "status": "UNKNOWN",
                "confidence": 0.0,
                "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "details": "Empty domain"
            }

        domain_lower = domain.strip().lower()
        is_hit = domain_lower in BLACKLIST

        return {
            "provider": self.name,
            "status": "SUSPICIOUS" if is_hit else "UNKNOWN",
            "confidence": 0.5 if is_hit else 0.0,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details": "Historical training-source match; current maliciousness unconfirmed" if is_hit else "No historical match; safety unconfirmed"
        }


class ExternalAPIProvider(ReputationProvider):
    """External Reputation API Provider skeleton (e.g. VirusTotal or Google Safe Browsing)."""

    def __init__(self, provider_name: str = "external_api", api_key_env: str = "REPUTATION_API_KEY"):
        self._name = provider_name
        self.api_key = os.environ.get(api_key_env, "").strip()

    @property
    def name(self) -> str:
        return self._name

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if not self.api_key:
            return {
                "provider": self.name,
                "status": "UNAVAILABLE",
                "confidence": 0.0,
                "checked_at": now_iso,
                "details": "API key not configured"
            }

        try:
            # Placeholder for external HTTP lookup with explicit 2.0s timeout
            # In actual deployment, perform requests.get/post here.
            return {
                "provider": self.name,
                "status": "UNAVAILABLE",
                "confidence": 0.0,
                "checked_at": now_iso,
                "details": "External provider integration is not implemented"
            }
        except requests.Timeout:
            return {
                "provider": self.name,
                "status": "UNAVAILABLE",
                "confidence": 0.0,
                "checked_at": now_iso,
                "details": "Provider timeout"
            }
        except Exception as e:
            return {
                "provider": self.name,
                "status": "ERROR",
                "confidence": 0.0,
                "checked_at": now_iso,
                "details": "Provider unavailable"
            }


class MockReputationProvider(ReputationProvider):
    """Mock Reputation Provider for deterministic unit testing."""

    def __init__(self, provider_name: str = "mock_provider", return_status: str = "SAFE", confidence: float = 0.9):
        self._name = provider_name
        self.return_status = return_status
        self.confidence = confidence

    @property
    def name(self) -> str:
        return self._name

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "status": self.return_status,
            "confidence": self.confidence,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details": f"Mock result: {self.return_status}"
        }


class MultiProviderAggregator:
    """Aggregates multiple reputation provider responses into evidence breakdown."""

    def __init__(self, providers: List[ReputationProvider] = None):
        if providers is None:
            providers = [LocalBlacklistProvider()]
        self.providers = providers

    def aggregate_lookup(self, domain: str) -> Dict[str, Any]:
        provider_results: List[Dict[str, Any]] = []

        for provider in self.providers:
            try:
                res = provider.lookup_domain(domain)
                provider_results.append(res)
            except Exception as e:
                provider_results.append({
                    "provider": provider.name,
                    "status": "ERROR",
                    "confidence": 0.0,
                    "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "details": "Provider unavailable"
                })

        # Count statuses
        malicious_count = sum(1 for p in provider_results if p["status"] == "MALICIOUS")
        suspicious_count = sum(1 for p in provider_results if p["status"] == "SUSPICIOUS")
        safe_count = sum(1 for p in provider_results if p["status"] == "SAFE")
        unavailable_count = sum(1 for p in provider_results if p["status"] in ("UNAVAILABLE", "ERROR"))

        # Determine composite status
        if malicious_count > 0:
            composite_status = "MALICIOUS"
        elif suspicious_count > 0:
            composite_status = "SUSPICIOUS"
        elif safe_count == len(provider_results) and safe_count > 0:
            composite_status = "SAFE"
        elif unavailable_count == len(provider_results):
            composite_status = "UNAVAILABLE"
        else:
            composite_status = "UNKNOWN"

        return {
            "reputation_status": composite_status,
            "provider_count": len(provider_results),
            "malicious_provider_count": malicious_count,
            "suspicious_provider_count": suspicious_count,
            "safe_provider_count": safe_count,
            "providers": provider_results,
        }
