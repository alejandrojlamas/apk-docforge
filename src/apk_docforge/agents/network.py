from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.tools.static_extractors import (
    ExtractedString,
    find_domains,
    find_urls,
    ignored_signal_source,
)


SDK_PATTERNS = {
    "Firebase": ["firebase", "google.firebase", "firebaseio.com"],
    "Firebase Crashlytics": ["crashlytics"],
    "Google Analytics": ["google-analytics", "app-measurement", "analytics.google"],
    "Sentry": ["sentry.io", "io.sentry"],
    "Supabase": ["supabase.co", "supabase"],
    "Stripe": ["stripe.com", "com.stripe"],
    "Braintree": ["braintree", "paypal.sdk"],
    "PayPal": ["paypal.com", "com.paypal"],
    "AdMob": ["admob", "google.android.gms.ads"],
    "Facebook SDK": ["facebook.com", "com.facebook"],
    "OneSignal": ["onesignal"],
}

CLIENT_PATTERNS = {
    "OkHttp": ["okhttp3", "okhttp"],
    "Retrofit": ["retrofit2", "retrofit"],
    "Volley": ["com.android.volley", "volley"],
    "gRPC": ["io.grpc", "grpc"],
    "WebSocket": ["websocket", "ws://", "wss://"],
    "GraphQL": ["graphql", "/graphql"],
    "Ktor": ["io.ktor", "ktor.client"],
}


class NetworkConnectionAgent(BaseAgent):
    name = "NetworkConnectionAgent"
    output_files = (
        "network_endpoints.json",
        "sdk_detection.json",
        "api_clients.json",
        "connection_map.json",
    )

    def run(self) -> AgentContext:
        strings = self._strings()
        urls = find_urls(strings)
        domains = find_domains(strings)
        endpoints = self._endpoints(urls, domains)
        sdks = self._detect_patterns(strings, SDK_PATTERNS)
        api_clients = self._detect_patterns(strings, CLIENT_PATTERNS)
        connection_map = self._connection_map(endpoints, sdks, api_clients)

        self.write_json(
            "network_endpoints.json",
            {"schema_version": "1.0", "endpoints": endpoints, "domains": domains},
        )
        self.write_json("sdk_detection.json", {"schema_version": "1.0", "sdks": sdks})
        self.write_json("api_clients.json", {"schema_version": "1.0", "api_clients": api_clients})
        self.write_json(
            "connection_map.json",
            {"schema_version": "1.0", "connections": connection_map},
        )
        self.context.data["network_endpoints"] = endpoints
        self.context.data["domains"] = domains
        self.context.data["sdk_detection"] = sdks
        self.context.data["api_clients"] = api_clients
        self.context.data["connection_map"] = connection_map
        return self.context

    def _strings(self) -> list[ExtractedString]:
        return [
            ExtractedString(
                value=row.get("value", ""),
                path=row.get("path", ""),
                line_number=row.get("line_number"),
                source=row.get("source", "archive"),
            )
            for row in self.context.data.get("static_strings", [])
            if row.get("value") and not ignored_signal_source(str(row.get("path", "")))
        ]

    def _endpoints(
        self, urls: list[dict[str, Any]], domains: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []
        seen = set()
        for row in urls:
            url = str(row["url"])
            parsed = urlparse(url)
            key = (parsed.scheme, parsed.netloc, parsed.path)
            if key in seen:
                continue
            seen.add(key)
            endpoint_type = self._endpoint_type(url)
            endpoints.append(
                {
                    "url": url,
                    "scheme": parsed.scheme,
                    "domain": parsed.netloc,
                    "path": parsed.path or "/",
                    "query_present": bool(parsed.query),
                    "method_hint": row.get("method_hint"),
                    "type": endpoint_type,
                    "status": row.get("status", "observed"),
                    "confidence": row.get("confidence", 0.7),
                    "evidence_refs": row.get("evidence_refs", []),
                }
            )
        domain_values = {str(item.get("domain")) for item in domains if item.get("domain")}
        endpoint_domains = {str(item["domain"]) for item in endpoints if item.get("domain")}
        for domain in sorted(domain_values - endpoint_domains):
            if not domain:
                continue
            evidence = _as_evidence_list(
                next(
                    (item.get("evidence_refs", []) for item in domains if item.get("domain") == domain),
                    [],
                )
            )
            endpoints.append(
                {
                    "url": None,
                    "scheme": None,
                    "domain": domain,
                    "path": None,
                    "query_present": False,
                    "method_hint": None,
                    "type": "domain",
                    "status": "observed",
                    "confidence": 0.55,
                    "evidence_refs": evidence,
                }
            )
        return endpoints

    def _endpoint_type(self, url: str) -> str:
        lowered = url.lower()
        if lowered.startswith(("ws://", "wss://")):
            return "websocket"
        if "graphql" in lowered:
            return "graphql"
        if "grpc" in lowered:
            return "grpc"
        return "rest_or_http"

    def _detect_patterns(
        self, strings: list[ExtractedString], patterns: dict[str, list[str]]
    ) -> list[dict[str, Any]]:
        detected = []
        lower_rows = [(item, item.value.lower()) for item in strings]
        for name, needles in patterns.items():
            evidence = []
            for item, lowered in lower_rows:
                if any(needle.lower() in lowered for needle in needles):
                    evidence.append(
                        {
                            "path": item.path,
                            "line_number": item.line_number,
                            "kind": "string",
                            "description": f"Marker for {name} detected.",
                        }
                    )
                    if len(evidence) >= 5:
                        break
            detected.append(
                {
                    "name": name,
                    "status": "observed" if evidence else "unknown",
                    "confidence": 0.8 if evidence else 0.0,
                    "evidence_refs": evidence,
                }
            )
        return detected

    def _connection_map(
        self,
        endpoints: list[dict[str, Any]],
        sdks: list[dict[str, Any]],
        api_clients: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        by_path: dict[str, list[str]] = defaultdict(list)
        for endpoint in endpoints:
            for evidence in _as_evidence_list(endpoint.get("evidence_refs", [])):
                path = evidence.get("path")
                if isinstance(path, str) and path:
                    by_path[path].append(str(endpoint.get("domain") or endpoint.get("url")))
        connections = []
        observed_clients = [item["name"] for item in api_clients if item["status"] == "observed"]
        observed_sdks = [item["name"] for item in sdks if item["status"] == "observed"]
        for path, targets in sorted(by_path.items()):
            connections.append(
                {
                    "source_path": path,
                    "targets": sorted(set(targets)),
                    "api_clients_related": observed_clients,
                    "sdks_related": observed_sdks,
                    "status": "inferred",
                    "confidence": 0.55,
                    "evidence_refs": [
                        {
                            "path": path,
                            "kind": "derived",
                            "description": "Endpoint/domain and SDK/client markers appeared in static strings.",
                        }
                    ],
                }
            )
        return connections


def _as_evidence_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
