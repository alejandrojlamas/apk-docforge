from __future__ import annotations

from typing import Any

from apk_docforge.renderers.markdown import evidence_label, md_table
from apk_docforge.renderers.mermaid import navigation_graph


def render_codex_prompt(data: dict[str, Any]) -> str:
    identity = data.get("identity", {})
    features = data.get("features", [])
    screens = data.get("screens", [])
    screens_dynamic = data.get("screens_dynamic", [])
    ui_elements = data.get("ui_elements", [])
    ui_elements_dynamic = data.get("ui_elements_dynamic", [])
    endpoints = data.get("endpoints", [])
    permissions = data.get("permissions", [])
    components = data.get("components", {})
    findings = data.get("findings", [])
    protection_controls = data.get("protection_controls", [])
    authorization_boundaries = data.get("authorization_boundaries", [])
    bypass_policy = data.get("bypass_policy", {})
    app_understanding = data.get("app_understanding", {})
    reconstruction_brief = data.get("reconstruction_brief", {})
    storage = _storage(features)
    lines = [
        "# Prompt maestro para registrar ingeniería inversa Android",
        "",
        "## Rol",
        (
            "Actúa como documentalista técnico de ingeniería inversa autorizada. Tu tarea es "
            "convertir los JSON y artefactos de `apk-docforge` en un registro claro en lenguaje "
            "natural: qué es la app, para qué sirve, cómo funciona, qué pantallas tiene, qué "
            "conexiones usa, qué permisos solicita, qué riesgos aparecen y qué partes quedan unknown."
        ),
        "",
        "## Objetivo",
        (
            "Crear documentación humana de la ingeniería inversa de la aplicación analizada. "
            "No implementes una app, no generes código de reconstrucción y no diseñes bypasses "
            "salvo que el usuario pida explícitamente una tarea posterior permitida. Este prompt "
            "sirve para registrar conocimiento, no para clonar ni evadir controles."
        ),
        "",
        "## Reglas de documentación",
        "1. Usa los JSON adjuntos como fuente de verdad.",
        "2. No inventes funcionalidades, pantallas, endpoints ni flujos sin evidencia.",
        "3. Separa siempre `observed`, `inferred` y `unknown`.",
        "4. Cada afirmación importante debe incluir evidencia o indicar que es una inferencia.",
        "5. Mantén `confidence_score` cuando exista y baja confianza cuando la evidencia sea indirecta.",
        "6. No propongas bypasses de licencia, pago, DRM, autenticación, certificate pinning ni anti-tamper.",
        "7. No asumas comportamiento runtime si el análisis fue estático.",
        "8. Si hay contradicciones o datos débiles, escríbelos como limitaciones o preguntas abiertas.",
        "",
        "## Formato de salida esperado",
        "Genera un documento en lenguaje natural con esta estructura:",
        "- Resumen ejecutivo.",
        "- Identidad y cadena de custodia.",
        "- Qué es la app y para qué sirve.",
        "- Cómo funciona por dentro a nivel funcional.",
        "- Pantallas, navegación, botones y acciones.",
        "- Funcionalidades detectadas con evidencia.",
        "- Conexiones, endpoints, repositorios, SDKs y clientes HTTP.",
        "- Permisos, privacidad y datos probablemente tratados.",
        "- Componentes Android y superficie expuesta.",
        "- Almacenamiento local y estado offline/cache.",
        "- Hallazgos de seguridad y controles de protección observados.",
        "- Limitaciones, unknowns y preguntas abiertas.",
        "- Apéndice de evidencia con rutas/JSON relevantes.",
        "",
        "## Artefactos de referencia",
        "- `app_understanding.json`: resumen funcional normalizado.",
        "- `source_metadata.json`: metadatos públicos o de provenance.",
        "- `manifest.json`, `components.json`, `permissions.json`, `deep_links.json`: base Android.",
        "- `features.json`, `feature_evidence_map.json`, `confidence_report.json`: funcionalidades.",
        "- `static_screens.json`, `ui_elements_static.json`: pantallas y elementos estáticos.",
        "- `network_endpoints.json`, `sdk_detection.json`, `api_clients.json`: red y SDKs.",
        "- `security_findings.json`, `privacy_risks.json`, `control_boundary_assessment.json`: auditoría.",
        "- `reconstruction_brief.json`: usar solo como contexto opcional si luego se pide plan de reconstrucción.",
        "",
        "## Paquete de evidencia de esta app",
        "",
        "### Identidad",
        f"- Nombre: {identity.get('app_name') or 'unknown'}",
        f"- Package name: {identity.get('package_name') or 'unknown'}",
        f"- Version name: {identity.get('version_name') or 'unknown'}",
        f"- Version code: {identity.get('version_code') or 'unknown'}",
        f"- Min SDK: {identity.get('min_sdk') or 'unknown'}",
        f"- Target SDK: {identity.get('target_sdk') or 'unknown'}",
        f"- Firma/certificado: {identity.get('certificate') or 'unknown'}",
        f"- Fuente: {identity.get('source') or 'local_file'}",
        f"- SHA256: {identity.get('sha256') or 'unknown'}",
        f"- Fecha de análisis: {identity.get('analysis_date') or 'unknown'}",
        f"- Modo de análisis: {identity.get('mode') or 'static'}",
        "",
        "### Entendimiento funcional",
        f"- Qué es: {app_understanding.get('what_it_is') or 'unknown'}",
        f"- Para qué sirve: {app_understanding.get('purpose') or 'unknown'}",
        f"- Confidence: {app_understanding.get('confidence_score', 'unknown')}",
        f"- Evidencia: {evidence_label(app_understanding.get('evidence_refs', []))}",
        "- Observado directamente: consultar fuente/metadatos, pantallas, permisos y endpoints con estado `observed`.",
        "- Inferido por nombres/código/recursos: funcionalidades y flujos con estado `inferred` y confidence_score.",
        "- Desconocido: flujos runtime, login real, respuestas de servidor y acciones dinámicas no ejecutadas.",
        "",
        "### Cómo funciona la app",
        _how_it_works_section(app_understanding),
        "",
        "### Flujos principales registrados",
        md_table(
            ["Flujo", "Descripción", "Estado", "Confidence", "Evidencia"],
            [
                [
                    item.get("name"),
                    item.get("description"),
                    item.get("status"),
                    item.get("confidence_score"),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in app_understanding.get("core_flows", [])
            ],
        ),
        "### Modelos de datos inferidos para documentación",
        _data_models_section(reconstruction_brief),
        "",
        "### Funcionalidades detectadas",
        md_table(
            [
                "Funcionalidad",
                "Categoría",
                "Evidencia",
                "Confidence",
                "Pantallas relacionadas",
                "Endpoints/SDKs relacionados",
                "Riesgos/notas",
            ],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    evidence_label(item.get("evidence_refs", [])),
                    item.get("confidence_score", item.get("confidence")),
                    ", ".join(item.get("related_screens", [])) or "unknown",
                    ", ".join(item.get("related_endpoints", [])) or "unknown",
                    ", ".join(item.get("risks_or_notes", [])) or "unknown",
                ]
                for item in features
            ],
        ),
        "### Pantallas",
        _screens_section(screens, ui_elements),
        "### Pantallas dinámicas",
        _dynamic_screens_section(screens_dynamic, ui_elements_dynamic),
        "### Mapa de navegación",
        "```mermaid",
        navigation_graph(screens, ui_elements).rstrip(),
        "```",
        "",
        _blocked_flows_section(data.get("blocked_flows", [])),
        "",
        "### Conexiones",
        md_table(
            ["Dominios/Endpoints", "Método", "Cliente/Tipo", "SDKs", "Clases relacionadas", "Datos sensibles probables"],
            [
                [
                    item.get("url") or item.get("domain"),
                    item.get("method_hint") or "unknown",
                    item.get("type") or "unknown",
                    ", ".join(data.get("observed_sdks", [])) or "unknown",
                    evidence_label(item.get("evidence_refs", [])),
                    "unknown",
                ]
                for item in endpoints
            ],
        ),
        "### Permisos y privacidad",
        md_table(
            ["Permiso", "Justificación probable", "Evidencia", "Riesgo", "Recomendación"],
            [
                [
                    item.get("name"),
                    item.get("justification_probable"),
                    evidence_label(item.get("evidence_refs", [])),
                    item.get("risk"),
                    "Verificar necesidad y consentimiento asociado.",
                ]
                for item in permissions
            ],
        ),
        "### Componentes Android",
        _components_section(components),
        "### Almacenamiento local",
        storage,
        "### Hallazgos de seguridad",
        md_table(
            ["Severidad", "Título", "Evidencia", "Impacto", "Recomendación", "Limitaciones"],
            [
                [
                    item.get("severity"),
                    item.get("title"),
                    evidence_label(item.get("evidence_refs", [])),
                    item.get("impact"),
                    item.get("recommendation"),
                    "Static signal; validate manually.",
                ]
                for item in findings
            ],
        ),
        "### Controles de proteccion y fronteras",
        _protection_boundaries_section(protection_controls, authorization_boundaries, bypass_policy),
        "### Matriz de pruebas sugeridas para validar la documentación",
        md_table(
            ["Flujo", "Precondición", "Pasos", "Resultado esperado", "Datos de prueba", "Prioridad"],
            _test_matrix(features, screens),
        ),
        "### Limitaciones",
        "- Ofuscación: ver `obfuscation_report.json`.",
        "- Código no decompilable: depende de jadx/apktool instalados.",
        "- Flujos detrás de login: unknown en static-only.",
        "- Falta de credenciales de prueba: no se ejecutó login real.",
        "- Análisis dinámico no ejecutado: esta ejecución fue exclusivamente estática.",
        "- Cert pinning o tráfico no visible sin autorización: no se intenta bypass.",
        "",
        "## Instrucciones finales para Codex",
        "A partir de este contexto:",
        "1. Redacta el registro de ingeniería inversa en lenguaje natural.",
        "2. Empieza por una explicación entendible para humanos y luego baja al detalle técnico.",
        "3. No inventes funcionalidades sin evidencia.",
        "4. No conviertas esto en una especificación para clonar la app salvo que el usuario lo pida después.",
        "5. Conserva evidencia, confidence y estado observed/inferred/unknown.",
        "6. Usa `unknown` cuando falte evidencia.",
        "7. No propongas bypasses de licencia, pago, DRM, autenticación ni controles de seguridad.",
        "",
    ]
    return "\n".join(lines).replace("\n\n\n", "\n\n")


def _screens_section(screens: list[dict[str, Any]], elements: list[dict[str, Any]]) -> str:
    if not screens:
        return "_No hay pantallas observadas._\n"
    lines = []
    for screen in screens:
        related = [item for item in elements if item.get("screen_hint") == screen.get("name")]
        buttons = [item for item in related if item.get("element_type") in {"button", "menu_item"}]
        inputs = [item for item in related if item.get("element_type") == "input"]
        lines.extend(
            [
                f"### {screen.get('name')}",
                f"- Nombre probable: {screen.get('name')}",
                f"- Activity/Fragment/Composable/layout relacionado: {screen.get('activity_or_fragment') or ', '.join(screen.get('related_layouts', [])) or 'unknown'}",
                f"- Elementos UI: {len(related)}",
                f"- Botones: {', '.join(_element_label(item) for item in buttons) or 'unknown'}",
                f"- Inputs: {', '.join(_element_label(item) for item in inputs) or 'unknown'}",
                "- Menús: consultar `ui_elements_static.json`.",
                "- Acciones esperadas: inferidas por texto/recurso cuando existe.",
                "- Acciones observadas: unknown en modo static-only.",
                f"- Evidencia: {evidence_label(screen.get('evidence_refs', []))}",
                "",
            ]
        )
    return "\n".join(lines)


def _components_section(components: dict[str, list[dict[str, Any]]]) -> str:
    lines = []
    for title, rows in [
        ("Activities", components.get("activities", [])),
        ("Services", components.get("services", [])),
        ("Receivers", components.get("receivers", [])),
        ("Providers", components.get("providers", [])),
    ]:
        lines.append(f"### {title}")
        lines.append(
            md_table(
                ["Name", "Exported", "Risk", "Intent filters / Deep links"],
                [
                    [
                        item.get("name"),
                        item.get("exported_effective", item.get("exported", "unknown")),
                        item.get("risk", "unknown"),
                        len(item.get("intent_filters", [])) + len(item.get("deep_links", [])),
                    ]
                    for item in rows
                ],
            )
        )
    return "\n".join(lines)


def _dynamic_screens_section(screens: list[dict[str, Any]], elements: list[dict[str, Any]]) -> str:
    if not screens:
        return "_No hay pantallas dinámicas observadas._\n"
    lines = []
    for screen in screens:
        related = [item for item in elements if item.get("screen_id") == screen.get("id")]
        buttons = [item for item in related if item.get("element_type") in {"button", "clickable"}]
        lines.extend(
            [
                f"### {screen.get('name')}",
                "- Fuente: UIAutomator dinámico",
                f"- Screenshot: {screen.get('screenshot') or 'unknown'}",
                f"- UI dump: {screen.get('uiautomator_dump') or 'unknown'}",
                f"- Elementos: {len(related)}",
                f"- Acciones observadas: {', '.join(_element_label(item) for item in buttons[:8]) or 'unknown'}",
                f"- Evidencia: {evidence_label(screen.get('evidence_refs', []))}",
                "",
            ]
        )
    return "\n".join(lines)


def _reconstruction_goal_section(
    understanding: dict[str, Any],
    brief: dict[str, Any],
    source_metadata: dict[str, Any],
) -> str:
    lines = [
        f"- Meta principal: {brief.get('codex_goal') or understanding.get('what_it_is') or 'unknown'}",
        f"- Fuente pública/permitida: {source_metadata.get('package_page_url') or source_metadata.get('metadata_source') or source_metadata.get('source') or 'unknown'}",
        f"- App base: {understanding.get('app_name') or source_metadata.get('app_name') or 'unknown'}",
        f"- Usuarios: {', '.join(understanding.get('primary_users', [])) or 'unknown'}",
        f"- Evidence refs: {evidence_label(brief.get('evidence_refs') or understanding.get('evidence_refs', []))}",
        "",
        "### Pantallas base para rehacer",
    ]
    screens = brief.get("screen_blueprint", [])
    if not screens:
        lines.append("- unknown")
    else:
        lines.extend(f"- {item.get('name')}: {item.get('description')}" for item in screens)
    return "\n".join(lines)


def _how_it_works_section(understanding: dict[str, Any]) -> str:
    rows = understanding.get("how_it_works", [])
    if not rows:
        return "- unknown\n"
    return "\n".join(
        f"- {item.get('step')}: status={item.get('status')}, confidence={item.get('confidence_score')}, "
        f"evidencia={evidence_label(item.get('evidence_refs', []))}"
        for item in rows
    )


def _mvp_scope_section(brief: dict[str, Any]) -> str:
    items = brief.get("recommended_mvp_scope", [])
    if not items:
        return "- unknown\n"
    return "\n".join(f"- {item}" for item in items) + "\n"


def _data_models_section(brief: dict[str, Any]) -> str:
    items = brief.get("core_data_models", [])
    if not items:
        return "- unknown\n"
    return "\n".join(f"- {item}" for item in items) + "\n"


def _reconstruction_backlog(brief: dict[str, Any]) -> str:
    items = brief.get("recommended_mvp_scope", [])
    if not items:
        return ""
    rows = ["- Épicas de reconstrucción:"]
    rows.extend(f"  - {item}" for item in items[:8])
    return "\n".join(rows)


def _blocked_flows_section(blocked_flows: list[dict[str, Any]]) -> str:
    if not blocked_flows:
        return "- Flujos bloqueados: unknown o no observados."
    rows = [
        f"- Flujos bloqueados: {item.get('type')} / {item.get('label')} / {item.get('reason')}"
        for item in blocked_flows
    ]
    return "\n".join(rows)


def _storage(features: list[dict[str, Any]]) -> str:
    markers = [item for item in features if item.get("category") == "local_storage"]
    status = "inferred" if markers else "unknown"
    return "\n".join(
        [
            f"- SharedPreferences: {status}",
            f"- SQLite/Room: {status}",
            "- Files/cache: unknown",
            "- Encrypted storage si se detecta: unknown",
            "- Riesgos: revisar hallazgos de almacenamiento y evidencia antes de afirmar datos sensibles.",
            "",
        ]
    )


def _protection_boundaries_section(
    controls: list[dict[str, Any]],
    boundaries: list[dict[str, Any]],
    policy: dict[str, Any],
) -> str:
    observed = [item for item in controls if item.get("status") != "unknown"]
    lines = [
        f"- Bypass implementado: {str(policy.get('bypass_implemented', False)).lower()}",
        f"- Bypass intentado: {str(policy.get('bypass_attempted', False)).lower()}",
        f"- Politica: {policy.get('reason') or 'Los controles se documentan sin evadirlos.'}",
        "",
        "### Controles detectados",
        md_table(
            ["Control", "Categoria", "Estado", "Bypass", "Confidence", "Evidencia"],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    item.get("status"),
                    item.get("bypass_status") or "prohibited_by_policy",
                    item.get("confidence_score", item.get("confidence")),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in observed
            ],
        ),
        "### Fronteras de autorizacion",
        md_table(
            ["Frontera", "Categoria", "Accion permitida", "Accion bloqueada", "Confidence", "Evidencia"],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    item.get("allowed_audit_action"),
                    item.get("blocked_action"),
                    item.get("confidence_score", item.get("confidence")),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in boundaries
            ],
        ),
    ]
    return "\n".join(lines)


def _test_matrix(features: list[dict[str, Any]], screens: list[dict[str, Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for screen in screens[:8]:
        rows.append(
            [
                f"Pantalla {screen.get('name')}",
                "APK instalada en emulador de pruebas autorizado",
                "Abrir app, navegar a la pantalla, registrar elementos visibles",
                "La pantalla muestra elementos esperados y no genera errores",
                "Datos de prueba no sensibles",
                "Media",
            ]
        )
    for feature in features[:8]:
        rows.append(
            [
                str(feature.get("name")),
                "Evidencia estática revisada",
                "Validar flujo en entorno de prueba sin acciones irreversibles",
                "El comportamiento coincide con la evidencia documentada",
                "Cuenta o datos de prueba si aplica",
                "Alta" if feature.get("category") in {"auth", "commerce"} else "Media",
            ]
        )
    return rows


def _element_label(item: dict[str, Any]) -> str:
    return str(item.get("visible_text") or item.get("resource_id") or item.get("tag") or "unknown")
