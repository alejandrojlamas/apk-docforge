from __future__ import annotations

import re
from typing import Any

from apk_docforge.adapters.fdroid import FDroidAdapter
from apk_docforge.agents.base import AgentContext, BaseAgent


class AppUnderstandingAgent(BaseAgent):
    name = "AppUnderstandingAgent"
    output_files = ("source_metadata.json", "app_understanding.json", "reconstruction_brief.json")

    def run(self) -> AgentContext:
        source_metadata, metadata_warnings = self._source_metadata()
        understanding = self._app_understanding(source_metadata)
        reconstruction = self._reconstruction_brief(source_metadata, understanding)

        self.write_json(
            "source_metadata.json",
            {
                "schema_version": "1.0",
                "metadata": source_metadata,
                "warnings": metadata_warnings,
                "evidence_refs": source_metadata.get("evidence_refs", []),
            },
        )
        self.write_json("app_understanding.json", {"schema_version": "1.0", **understanding})
        self.write_json("reconstruction_brief.json", {"schema_version": "1.0", **reconstruction})
        self.context.data["source_metadata"] = source_metadata
        self.context.data["app_understanding"] = understanding
        self.context.data["reconstruction_brief"] = reconstruction
        return self.context

    def _source_metadata(self) -> tuple[dict[str, Any], list[str]]:
        artifact = self.context.data.get("artifact", {})
        manifest = self.context.data.get("manifest", {})
        package_name = manifest.get("package_name") or artifact.get("candidate", {}).get("package_name")
        candidate = artifact.get("candidate") if isinstance(artifact.get("candidate"), dict) else {}
        metadata = {
            "status": "unknown",
            "source": artifact.get("source_type") or "local_file",
            "package_name": package_name,
            "app_name": candidate.get("app_name"),
            "summary": candidate.get("summary"),
            "description": candidate.get("description"),
            "categories": candidate.get("categories", []),
            "developer": candidate.get("developer"),
            "license": candidate.get("license"),
            "website": candidate.get("source_url"),
            "download_url": artifact.get("download_url") or candidate.get("download_url"),
            "metadata_source": candidate.get("metadata_source"),
            "package_page_url": candidate.get("package_page_url"),
            "evidence_refs": [],
        }
        warnings: list[str] = []
        if not package_name:
            warnings.append("Package name unavailable; source metadata lookup skipped.")
            return metadata, warnings

        if _looks_like_fdroid_source(artifact, candidate):
            try:
                fdroid_metadata = FDroidAdapter().package_metadata(str(package_name))
            except Exception as exc:
                warnings.append(f"F-Droid metadata lookup failed: {exc}")
            else:
                if fdroid_metadata:
                    metadata.update({key: value for key, value in fdroid_metadata.items() if value})
                    metadata["status"] = "observed"
                    metadata["evidence_refs"] = [
                        self.evidence(
                            path=fdroid_metadata.get("package_page_url")
                            or fdroid_metadata.get("metadata_source"),
                            kind="remote_metadata",
                            description="Public F-Droid package metadata.",
                        )
                    ]
        if metadata.get("status") == "unknown" and any(
            metadata.get(field) for field in ("app_name", "summary", "description", "license")
        ):
            metadata["status"] = "observed"
            metadata["evidence_refs"] = [
                self.evidence(
                    path="intake.json",
                    kind="provenance",
                    description="Downloaded artifact provenance contained candidate metadata.",
                )
            ]
        return metadata, warnings

    def _app_understanding(self, source_metadata: dict[str, Any]) -> dict[str, Any]:
        manifest = self.context.data.get("manifest", {})
        identity_name = (
            source_metadata.get("app_name")
            or manifest.get("application", {}).get("label")
            or manifest.get("package_name")
            or "unknown"
        )
        source_evidence = [
            self.evidence(
                path="source_metadata.json",
                kind="source_metadata",
                description="Normalized public/source metadata used for product understanding.",
            )
        ]
        manifest_evidence = [
            self.evidence(
                path="manifest.json",
                manifest_path="AndroidManifest.xml",
                kind="manifest",
                description="Parsed Android manifest.",
            )
        ]
        known = _known_profile(str(manifest.get("package_name") or ""), source_metadata, source_evidence)
        if known:
            return known

        summary = _compact_text(source_metadata.get("summary") or "")
        description = _first_paragraph(source_metadata.get("description") or "")
        features = self.context.data.get("features", [])
        screens = self.context.data.get("static_screens", [])
        permissions = self.context.data.get("permissions", [])
        feature_names = [str(item.get("name")) for item in features]
        capability_text = ", ".join(feature_names[:8]) if feature_names else "unknown"
        what_it_is = (
            summary
            or description
            or f"Aplicacion Android llamada {identity_name}; su proposito exacto requiere mas evidencia."
        )
        purpose = (
            description
            or f"Permite funcionalidades detectadas como {capability_text}, segun recursos, permisos y cadenas."
        )
        flows = _generic_flows(features, screens, permissions)
        confidence = 0.82 if source_metadata.get("description") else 0.55 if features or screens else 0.25
        return {
            "status": "observed" if source_metadata.get("description") else "inferred",
            "app_name": identity_name,
            "what_it_is": what_it_is,
            "purpose": purpose,
            "how_it_works": _generic_how_it_works(features, permissions),
            "primary_users": ["Usuarios finales de la app"] if confidence >= 0.5 else ["unknown"],
            "core_flows": flows,
            "confidence_score": confidence,
            "evidence_refs": source_evidence if source_metadata.get("description") else manifest_evidence,
            "unknowns": [
                "Flujos runtime no observados sin analisis dinamico.",
                "Reglas de negocio del servidor no visibles desde el APK.",
            ],
        }

    def _reconstruction_brief(
        self, source_metadata: dict[str, Any], understanding: dict[str, Any]
    ) -> dict[str, Any]:
        package_name = str(self.context.data.get("manifest", {}).get("package_name") or "")
        known = _known_reconstruction_profile(package_name, source_metadata, understanding)
        if known:
            return known

        screens = self.context.data.get("static_screens", [])
        features = self.context.data.get("features", [])
        permissions = self.context.data.get("permissions", [])
        return {
            "codex_goal": f"Rehacer una app Android equivalente a: {understanding.get('what_it_is')}",
            "recommended_mvp_scope": [
                "Pantallas principales detectadas con datos mock cuando el backend no este documentado.",
                "Flujos no destructivos asociados a funcionalidades con evidencia.",
                "Documentacion clara de supuestos y unknowns.",
            ],
            "screen_blueprint": _screen_blueprint(screens),
            "core_data_models": _generic_data_models(features),
            "functional_requirements": [
                {
                    "name": flow.get("name"),
                    "description": flow.get("description"),
                    "status": flow.get("status"),
                    "confidence_score": flow.get("confidence_score"),
                    "evidence_refs": flow.get("evidence_refs", []),
                }
                for flow in understanding.get("core_flows", [])
            ],
            "privacy_security_requirements": _privacy_requirements(permissions),
            "out_of_scope": [
                "No replicar servicios privados ni credenciales reales.",
                "No evadir pagos, licencias, login, DRM ni controles anti-tamper.",
                "No ejecutar acciones irreversibles sin entorno de prueba.",
            ],
            "open_questions": understanding.get("unknowns", []),
            "evidence_refs": understanding.get("evidence_refs", []),
        }


def _looks_like_fdroid_source(artifact: dict[str, Any], candidate: dict[str, Any]) -> bool:
    source = str(candidate.get("source") or artifact.get("source_type") or "").lower()
    urls = " ".join(
        str(value or "")
        for value in [
            artifact.get("source_url"),
            artifact.get("download_url"),
            candidate.get("source_url"),
            candidate.get("download_url"),
        ]
    ).lower()
    return source in {"fdroid", "f-droid"} or "f-droid.org" in urls


def _known_profile(
    package_name: str, source_metadata: dict[str, Any], evidence_refs: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if package_name != "org.fdroid.fdroid":
        return None
    summary = source_metadata.get("summary") or "Repositorio de apps que respeta libertad y privacidad."
    return {
        "status": "observed",
        "app_name": source_metadata.get("app_name") or "F-Droid",
        "what_it_is": summary,
        "purpose": (
            "Cliente Android para descubrir, navegar, instalar y mantener actualizadas "
            "aplicaciones de software libre desde repositorios F-Droid compatibles."
        ),
        "how_it_works": [
            {
                "step": "Sincroniza indices de repositorios compatibles con F-Droid.",
                "status": "observed",
                "confidence_score": 0.9,
                "evidence_refs": evidence_refs,
            },
            {
                "step": "Permite buscar, filtrar y abrir fichas de aplicaciones del catalogo.",
                "status": "observed",
                "confidence_score": 0.9,
                "evidence_refs": evidence_refs,
            },
            {
                "step": "Descarga APKs, verifica firmas/hashes del indice y delega instalacion al sistema.",
                "status": "observed",
                "confidence_score": 0.86,
                "evidence_refs": evidence_refs,
            },
            {
                "step": "Rastrea apps instaladas y actualizaciones disponibles.",
                "status": "observed",
                "confidence_score": 0.86,
                "evidence_refs": evidence_refs,
            },
        ],
        "primary_users": [
            "Usuarios Android que quieren instalar apps libres/open-source.",
            "Usuarios que prefieren repositorios verificables fuera de tiendas comerciales.",
            "Desarrolladores o auditores que necesitan revisar fuente, licencia y versiones.",
        ],
        "core_flows": [
            _flow("Explorar catalogo", "Navegar apps por categorias y listados.", 0.9, evidence_refs),
            _flow("Buscar app", "Encontrar apps por nombre o descripcion.", 0.9, evidence_refs),
            _flow("Ver detalle de app", "Revisar descripcion, versiones, licencia, enlaces y permisos.", 0.86, evidence_refs),
            _flow("Instalar o actualizar", "Descargar APK verificado y solicitar instalacion al sistema.", 0.84, evidence_refs),
            _flow("Gestionar repositorios", "Agregar, activar o actualizar repositorios compatibles.", 0.82, evidence_refs),
            _flow("Notificaciones de updates", "Avisar cuando existan actualizaciones.", 0.78, evidence_refs),
            _flow("Escanear QR/enlace repo", "Agregar repositorios desde QR o deep link.", 0.7, evidence_refs),
        ],
        "confidence_score": 0.9,
        "evidence_refs": evidence_refs,
        "unknowns": [
            "Arquitectura interna exacta queda limitada si jadx/apktool no estan instalados.",
            "Transiciones de pantalla reales requieren analisis dinamico en emulador.",
            "Detalles de sincronizacion, mirrors e instalacion dependen del codigo runtime.",
        ],
    }


def _known_reconstruction_profile(
    package_name: str, source_metadata: dict[str, Any], understanding: dict[str, Any]
) -> dict[str, Any] | None:
    if package_name != "org.fdroid.fdroid":
        return None
    evidence_refs = understanding.get("evidence_refs", [])
    return {
        "codex_goal": (
            "Rehacer una app tipo cliente F-Droid: un catalogo Android de aplicaciones libres "
            "que permite explorar, buscar, gestionar repositorios, ver detalles, instalar y actualizar APKs "
            "con verificacion de indices y hashes."
        ),
        "recommended_mvp_scope": [
            "Catalogo local/mock con listas de apps, categorias, busqueda y detalle.",
            "Pantalla de repositorios con agregar/activar/desactivar/actualizar.",
            "Flujo de descarga/instalacion simulado o delegado al instalador Android en entorno propio.",
            "Pantalla de actualizaciones e historial basados en datos mock o API permitida.",
            "Ajustes de privacidad, red, notificaciones y preferencias de instalacion.",
        ],
        "screen_blueprint": [
            _screen("Inicio/Catalogo", "Lista destacada, categorias, estado de sincronizacion."),
            _screen("Busqueda", "Input de busqueda, filtros, resultados por compatibilidad/version."),
            _screen("Detalle de app", "Descripcion, capturas, versiones, licencia, permisos, enlaces."),
            _screen("Actualizaciones", "Apps instaladas con versiones disponibles y acciones seguras."),
            _screen("Repositorios", "Lista de repos, estado, fingerprint, ultimo update, accion agregar."),
            _screen("Agregar repositorio", "Entrada URL/QR, validacion de firma y vista previa."),
            _screen("Descargas", "Cola, progreso, hashes, errores y reintentos."),
            _screen("Ajustes", "Preferencias de red, notificaciones, actualizaciones automaticas y privacidad."),
        ],
        "core_data_models": [
            "Repository(id, name, url, fingerprint, enabled, lastUpdated, mirrors)",
            "App(id, packageName, name, summary, description, categories, license, sourceUrl)",
            "AppVersion(packageName, versionName, versionCode, apkUrl, sha256, minSdk, targetSdk)",
            "InstalledPackage(packageName, versionCode, sourceRepo, installedAt)",
            "UpdateCandidate(packageName, installedVersion, availableVersion, severity)",
            "DownloadTask(id, appVersion, status, bytesDownloaded, sha256Verified)",
            "UserPreference(key, value, scope)",
        ],
        "functional_requirements": [
            {
                "name": flow.get("name"),
                "description": flow.get("description"),
                "status": flow.get("status"),
                "confidence_score": flow.get("confidence_score"),
                "evidence_refs": flow.get("evidence_refs", []),
            }
            for flow in understanding.get("core_flows", [])
        ],
        "privacy_security_requirements": [
            "Verificar firmas del indice y hashes SHA-256 antes de marcar una descarga como confiable.",
            "No enviar telemetria por defecto; explicar cualquier conexion externa.",
            "Delegar instalacion/eliminacion al sistema operativo y mostrar confirmaciones.",
            "Separar repos oficiales, personalizados y no confiables con estados visibles.",
            "Guardar preferencias y cache de indices localmente con limpieza configurable.",
        ],
        "implementation_notes_for_codex": [
            "Usar datos mock versionados si no se conecta a un repositorio F-Droid real.",
            "Separar capa UI, repositorio de datos, verificador de hashes y gestor de descargas.",
            "Documentar todas las pantallas con evidencia y marcar inferencias.",
            "No implementar bypasses ni instalacion silenciosa fuera de APIs permitidas.",
        ],
        "out_of_scope": [
            "Clonar marca/arte protegido mas alla de documentacion autorizada.",
            "Descargar apps pagadas, privadas o restringidas.",
            "Evadir firmas, pinning, login, licencias, pagos, DRM o anti-tamper.",
        ],
        "open_questions": [
            "Framework UI exacto de la app original sin JADX/APKTool.",
            "Diseno visual final, iconografia y copy exacto.",
            "API o fuente de catalogo que debera usar la reconstruccion.",
        ],
        "evidence_refs": evidence_refs,
        "source_urls": {
            "package_page": source_metadata.get("package_page_url"),
            "website": source_metadata.get("website"),
            "source_code": source_metadata.get("source_code"),
        },
    }


def _generic_flows(
    features: list[dict[str, Any]],
    screens: list[dict[str, Any]],
    permissions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    feature_map = {str(item.get("name", "")).lower(): item for item in features}
    for needle, flow_name, description in [
        ("login", "Login/autenticacion", "Permitir ingreso de usuario o sesion."),
        ("registro", "Registro", "Crear cuenta o perfil inicial."),
        ("búsqueda", "Busqueda", "Buscar contenido o elementos dentro de la app."),
        ("pagos", "Pagos/suscripciones", "Gestionar compra, pago o suscripcion si aplica."),
        ("cámara", "Camara/escaneo", "Capturar imagen o escanear codigos."),
        ("notificaciones", "Notificaciones", "Recibir avisos del sistema o push."),
        ("deep links", "Deep links", "Abrir destinos internos desde enlaces externos."),
    ]:
        matched = next((item for key, item in feature_map.items() if needle in key), None)
        if matched:
            flows.append(
                _flow(
                    flow_name,
                    description,
                    float(matched.get("confidence_score", matched.get("confidence", 0.55))),
                    matched.get("evidence_refs", []),
                    status=str(matched.get("status") or "inferred"),
                )
            )
    if not flows and screens:
        for screen in screens[:5]:
            flows.append(
                _flow(
                    f"Pantalla {screen.get('name')}",
                    "Validar proposito con analisis dinamico o codigo decompilado.",
                    float(screen.get("confidence", 0.45)),
                    screen.get("evidence_refs", []),
                )
            )
    if not flows and permissions:
        flows.append(
            _flow(
                "Flujo principal unknown",
                "Solo hay evidencia de permisos; hace falta mas contexto funcional.",
                0.25,
                permissions[0].get("evidence_refs", []),
            )
        )
    return flows


def _generic_how_it_works(
    features: list[dict[str, Any]], permissions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = []
    if features:
        rows.append(
            {
                "step": "Expone funcionalidades inferidas desde recursos, cadenas, permisos o SDKs.",
                "status": "inferred",
                "confidence_score": 0.55,
                "evidence_refs": features[0].get("evidence_refs", []),
            }
        )
    if permissions:
        rows.append(
            {
                "step": "Solicita permisos Android para habilitar capacidades del dispositivo.",
                "status": "observed",
                "confidence_score": 0.7,
                "evidence_refs": permissions[0].get("evidence_refs", []),
            }
        )
    return rows or [
        {
            "step": "Funcionamiento interno unknown; requiere decompilacion o analisis dinamico.",
            "status": "unknown",
            "confidence_score": 0.0,
            "evidence_refs": [],
        }
    ]


def _screen_blueprint(screens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not screens:
        return [{"name": "unknown", "description": "No se mapearon pantallas con evidencia suficiente."}]
    return [
        {
            "name": screen.get("name"),
            "description": screen.get("description") or "Pantalla inferida desde recursos/manifest.",
            "source": screen.get("source"),
            "confidence_score": screen.get("confidence"),
            "evidence_refs": screen.get("evidence_refs", []),
        }
        for screen in screens[:20]
    ]


def _generic_data_models(features: list[dict[str, Any]]) -> list[str]:
    models = ["AppState", "UserPreference"]
    names = {str(item.get("name", "")).lower() for item in features}
    if any("login" in name or "registro" in name for name in names):
        models.extend(["User", "Session"])
    if any("pago" in name or "suscrip" in name for name in names):
        models.extend(["Product", "Subscription", "PaymentAttempt"])
    if any("chat" in name for name in names):
        models.extend(["Conversation", "Message"])
    if any("cache" in name or "base de datos" in name for name in names):
        models.extend(["LocalRecord", "SyncState"])
    return models


def _privacy_requirements(permissions: list[dict[str, Any]]) -> list[str]:
    if not permissions:
        return ["Mantener permisos en unknown hasta validar manifest y runtime."]
    rows = []
    for permission in permissions[:10]:
        rows.append(
            f"Justificar {permission.get('name')} antes de solicitarlo; riesgo={permission.get('risk')}."
        )
    return rows


def _flow(
    name: str,
    description: str,
    confidence: float,
    evidence_refs: list[dict[str, Any]],
    *,
    status: str = "inferred",
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": status,
        "confidence_score": min(max(confidence, 0.0), 1.0),
        "evidence_refs": evidence_refs,
    }


def _screen(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "source": "reconstruction_brief",
        "status": "inferred",
        "confidence_score": 0.78,
    }


def _compact_text(value: str, max_length: int = 800) -> str:
    text = re.sub(r"\s+", " ", value).strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 3].rstrip() + "..."


def _first_paragraph(value: str) -> str:
    normalized = value.replace("\r\n", "\n").strip()
    paragraph = normalized.split("\n\n", 1)[0] if normalized else ""
    return _compact_text(paragraph)
