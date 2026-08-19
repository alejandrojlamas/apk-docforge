const state = {
  lastUploadedPath: null,
  lastDownloadedPath: null,
  lastAnalysisId: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

document.addEventListener("DOMContentLoaded", () => {
  bindModeCards();
  bindUploadFlow();
  bindSearchFlow();
  bindDeviceFlow();
  bindSettingsFlow();
  bindUtilityActions();
  loadInitialData();
});

function bindModeCards() {
  $$(".mode-card").forEach((button) => {
    button.addEventListener("click", () => {
      $$(".mode-card").forEach((item) => item.classList.remove("is-active"));
      $$(".entry-panel").forEach((item) => item.classList.remove("is-active"));
      button.classList.add("is-active");
      const panel = document.getElementById(button.dataset.panel);
      if (panel) panel.classList.add("is-active");
    });
  });
}

function bindUploadFlow() {
  const fileInput = $("#apkFile");
  const selectedFile = $("#selectedFile");
  const dropZone = $("#dropZone");

  fileInput.addEventListener("change", () => {
    selectedFile.textContent = fileInput.files[0]?.name || "Ningun archivo seleccionado";
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
    });
  });

  dropZone.addEventListener("drop", (event) => {
    const files = event.dataTransfer?.files;
    if (!files?.length) return;
    fileInput.files = files;
    selectedFile.textContent = files[0].name;
  });

  $("#uploadForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter;
    setBusy(submit, true, "Procesando");
    resetProgress();
    try {
      const localPath = $("#localPath").value.trim();
      const mode = getSelectedMode();
      const device = $("#uploadDevice").value.trim();
      if (localPath) {
        await analyzePath(localPath, { mode, device });
        return;
      }
      if (!fileInput.files.length) {
        throw new Error("Selecciona un archivo APK, APKS o XAPK, o escribe una ruta local.");
      }
      setStep("source", "done");
      setStep("download", "active");
      const formData = new FormData();
      formData.append("file", fileInput.files[0]);
      const uploaded = await api("/api/upload", { method: "POST", body: formData });
      state.lastUploadedPath = uploaded.local_path;
      setStep("download", "done");
      setStep("quarantine", "done");
      showOutput(uploaded);
      await analyzePath(uploaded.local_path, { mode, device });
    } catch (error) {
      showError(error);
    } finally {
      setBusy(submit, false);
    }
  });
}

function bindSearchFlow() {
  $("#searchForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter;
    setBusy(submit, true, "Buscando");
    resetProgress();
    try {
      const query = $("#searchQuery").value.trim();
      const sources = $$("input[name='source']:checked").map((input) => input.value);
      if (!sources.length) throw new Error("Selecciona al menos una fuente permitida.");
      setStep("source", "active");
      const result = await api("/api/search", {
        method: "POST",
        body: JSON.stringify({ query, sources, limit: 8 }),
      });
      setStep("source", "done");
      renderCandidates(result.candidates || []);
      showOutput(result);
      if (!result.candidates?.length) {
        notify("No se encontraron candidatos descargables. Revisa fuente, permisos o allowlist.", "error");
      } else {
        notify("Candidatos encontrados. Elige descargar o descargar y analizar.", "ok");
      }
    } catch (error) {
      showError(error);
    } finally {
      setBusy(submit, false);
    }
  });

  $("#saveAllowlistShortcut").addEventListener("click", () => {
    $("#settingsPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    $("#officialAllowlist").focus();
  });
}

function bindDeviceFlow() {
  $("#deviceForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter;
    setBusy(submit, true, "Importando");
    resetProgress();
    try {
      setStep("source", "active");
      const result = await api("/api/import-device", {
        method: "POST",
        body: JSON.stringify({
          package: $("#devicePackage").value.trim(),
          device: $("#deviceSerial").value.trim() || null,
          out: $("#deviceOut").value.trim() || "downloads",
        }),
      });
      setStep("source", "done");
      setStep("download", "done");
      setStep("quarantine", "done");
      renderDeviceImport(result);
      showOutput(result);
      notify("APK importada desde dispositivo. Puedes analizarla desde el resultado.", "ok");
    } catch (error) {
      showError(error);
    } finally {
      setBusy(submit, false);
    }
  });
}

function bindSettingsFlow() {
  $("#settingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter;
    setBusy(submit, true, "Guardando");
    try {
      const payload = {
        documentation_provider: "deepseek",
        deepseek_api_key: $("#deepseekKey").value.trim() || undefined,
        clear_deepseek_api_key: $("#clearDeepseek").checked,
        official_url_allowlist: $("#officialAllowlist").value.trim(),
        google_play_credentials_json: $("#googleCredsPath").value.trim(),
        allow_dynamic: $("#allowDynamic").checked,
      };
      const result = await api("/api/settings", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      $("#deepseekKey").value = "";
      $("#clearDeepseek").checked = false;
      renderSettings(result);
      notify("Ajustes guardados localmente.", "ok");
    } catch (error) {
      showError(error);
    } finally {
      setBusy(submit, false);
    }
  });
}

function bindUtilityActions() {
  $$("[data-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.querySelector(button.dataset.jump);
      target?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
  $("#refreshAnalyses").addEventListener("click", loadAnalyses);
  $("#clearOutput").addEventListener("click", () => {
    $("#outputBox").textContent = "";
    notify("Salida limpia.");
  });
}

async function loadInitialData() {
  await Promise.allSettled([loadHealth(), loadSources(), loadSettings(), loadAnalyses()]);
}

async function loadHealth() {
  const badge = $("#healthBadge");
  try {
    const health = await api("/api/health");
    const available = Object.values(health.tools || {}).filter((tool) => tool.available).length;
    badge.textContent = `Servidor activo · ${available} herramientas`;
    badge.className = "status-pill ok";
  } catch {
    badge.textContent = "Servidor no disponible";
    badge.className = "status-pill error";
  }
}

async function loadSources() {
  const result = await api("/api/sources");
  const container = $("#sourceList");
  const sources = result.sources || [];
  if (!sources.length) {
    container.innerHTML = `<p class="empty-state">No hay fuentes configuradas.</p>`;
    return;
  }
  container.innerHTML = sources
    .map((source) => {
      const blocked = !source.enabled || String(source.policy_status).includes("DISABLED");
      const badge = blocked ? "Bloqueada" : "Lista";
      return `
        <div class="source-item">
          <div>
            <strong>${escapeHtml(source.name || source.type)}</strong>
            <small>${escapeHtml(source.policy_status || "UNKNOWN")}</small>
          </div>
          <span class="source-badge ${blocked ? "blocked" : ""}">${badge}</span>
        </div>
      `;
    })
    .join("");
}

async function loadSettings() {
  const settings = await api("/api/settings");
  renderSettings(settings);
}

async function loadAnalyses() {
  const result = await api("/api/analyses?limit=8");
  renderAnalyses(result.analyses || []);
}

function renderSettings(settings) {
  $("#officialAllowlist").value = settings.official_url_allowlist || "";
  $("#googleCredsPath").value = "";
  $("#allowDynamic").checked = Boolean(settings.allow_dynamic);
  const rows = [
    ["DeepSeek", settings.deepseek_api_key_configured ? "Configurado" : "Sin clave"],
    ["URL oficial", settings.official_url_hosts?.length ? settings.official_url_hosts.join(", ") : "Sin hosts"],
    ["Google Play", settings.google_play_credentials_configured ? "Credenciales listas" : "Sin credenciales"],
    ["Modo dinamico", settings.allow_dynamic ? "Permitido con dispositivo" : "Apagado por defecto"],
  ];
  $("#settingsState").innerHTML = rows
    .map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd></div>`)
    .join("");
}

function renderCandidates(candidates) {
  const container = $("#candidateResults");
  if (!candidates.length) {
    container.innerHTML = `<p class="empty-state">No hay candidatos. Prueba F-Droid, GitHub, una URL oficial allowlist o credenciales de Google Play Developer.</p>`;
    return;
  }
  container.innerHTML = candidates
    .map((candidate) => {
      const canDownload = Boolean(candidate.download_url);
      return `
        <article class="result-item">
          <h3>${escapeHtml(candidate.app_name || candidate.package_name || "App sin nombre")}</h3>
          <p class="meta-line">${escapeHtml(candidate.package_name || "package desconocido")} · ${escapeHtml(candidate.source || "fuente desconocida")} · ${escapeHtml(candidate.version_name || "version desconocida")}</p>
          <p class="meta-line">${escapeHtml(candidate.download_url || candidate.source_url || "sin URL descargable")}</p>
          <div class="item-actions">
            <button class="secondary-button" type="button" data-download="${candidate.id}" ${canDownload ? "" : "disabled"}>Descargar</button>
            <button class="primary-button" type="button" data-download-analyze="${candidate.id}" ${canDownload ? "" : "disabled"}>Descargar y analizar</button>
          </div>
        </article>
      `;
    })
    .join("");

  $$("[data-download]").forEach((button) => {
    button.addEventListener("click", () => downloadCandidate(button.dataset.download, { analyze: false, button }));
  });
  $$("[data-download-analyze]").forEach((button) => {
    button.addEventListener("click", () => downloadCandidate(button.dataset.downloadAnalyze, { analyze: true, button }));
  });
}

function renderDeviceImport(result) {
  const container = $("#deviceResults");
  const artifacts = result.artifacts || [];
  if (!artifacts.length) {
    container.innerHTML = `<p class="empty-state">No se importaron APKs desde el dispositivo.</p>`;
    return;
  }
  container.innerHTML = artifacts
    .map((artifact, index) => `
      <article class="result-item">
        <h3>${escapeHtml(result.package_name)} · APK ${index + 1}</h3>
        <p class="meta-line">${escapeHtml(artifact.local_path || "sin ruta local")}</p>
        <p class="meta-line">SHA256 ${escapeHtml(artifact.sha256 || "no calculado")}</p>
        <div class="item-actions">
          <button class="primary-button" type="button" data-analyze-path="${escapeHtml(artifact.local_path || "")}" ${artifact.local_path ? "" : "disabled"}>Analizar esta APK</button>
        </div>
      </article>
    `)
    .join("");
  $$("[data-analyze-path]").forEach((button) => {
    button.addEventListener("click", () => analyzePath(button.dataset.analyzePath, { button }));
  });
}

function renderAnalyses(analyses) {
  const container = $("#analysisList");
  if (!analyses.length) {
    container.innerHTML = `<p class="empty-state">Aun no hay reportes generados.</p>`;
    return;
  }
  container.innerHTML = analyses
    .map((analysis) => `
      <article class="analysis-item">
        <h3>${escapeHtml(analysis.package_name || analysis.analysis_id || "Analisis")}</h3>
        <p class="meta-line">${escapeHtml(analysis.mode || "static")} · ${escapeHtml(analysis.status || "unknown")}</p>
        <div class="item-actions">
          <button class="secondary-button" type="button" data-report="${escapeHtml(analysis.analysis_id || analysis.db_analysis_id)}">Ver reporte</button>
          <button class="secondary-button" type="button" data-prompt="${escapeHtml(analysis.analysis_id || analysis.db_analysis_id)}">Ver prompt Codex</button>
        </div>
      </article>
    `)
    .join("");
  $$("[data-report]").forEach((button) => {
    button.addEventListener("click", () => loadTextArtifact(button.dataset.report, "report"));
  });
  $$("[data-prompt]").forEach((button) => {
    button.addEventListener("click", () => loadTextArtifact(button.dataset.prompt, "codex-prompt"));
  });
}

async function downloadCandidate(candidateId, { analyze = false, button } = {}) {
  setBusy(button, true, analyze ? "Descargando" : "Descargando");
  try {
    setStep("download", "active");
    const result = await api("/api/download", {
      method: "POST",
      body: JSON.stringify({ candidate_id: String(candidateId), out: "downloads" }),
    });
    state.lastDownloadedPath = result.local_path;
    setStep("download", "done");
    setStep("quarantine", "done");
    showOutput(result);
    notify("Descarga completada en cuarentena y carpeta local.", "ok");
    if (analyze) {
      await analyzePath(result.local_path);
    }
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function analyzePath(path, { mode = "static", device = "", button } = {}) {
  if (!path) throw new Error("Falta una ruta local para analizar.");
  setBusy(button, true, "Analizando");
  try {
    setStep("analysis", "active");
    const result = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({
        path,
        mode,
        device: device || null,
      }),
    });
    state.lastAnalysisId = result.analysis_id;
    setStep("analysis", "done");
    setStep("report", "done");
    showOutput(result);
    notify("Documentacion generada. Abre el reporte en la lista de reportes.", "ok");
    await loadAnalyses();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function loadTextArtifact(analysisId, kind) {
  try {
    const result = await api(`/api/analyses/${encodeURIComponent(analysisId)}/${kind}`);
    const text = result.report || result.codex_prompt || "";
    $("#outputBox").textContent = text;
    notify(kind === "report" ? "Reporte cargado." : "Prompt Codex cargado.", "ok");
  } catch (error) {
    showError(error);
  }
}

async function api(path, options = {}) {
  const headers = options.body instanceof FormData ? {} : { "Content-Type": "application/json" };
  const response = await fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = typeof payload === "object" ? payload.detail || payload.reason || payload : payload;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail, null, 2));
  }
  return payload;
}

function getSelectedMode() {
  return document.querySelector("input[name='mode']:checked")?.value || "static";
}

function setBusy(button, busy, busyText = "Procesando") {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
    return;
  }
  button.textContent = button.dataset.originalText || button.textContent;
  button.disabled = false;
}

function resetProgress() {
  $$("#progressSteps li").forEach((item) => item.classList.remove("active", "done"));
  setStep("source", "active");
}

function setStep(name, status) {
  const item = $(`#progressSteps [data-step="${name}"]`);
  if (!item) return;
  item.classList.remove("active", "done");
  item.classList.add(status);
}

function notify(message, kind = "") {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast ${kind}`.trim();
}

function showOutput(value) {
  $("#outputBox").textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function showError(error) {
  const message = error instanceof Error ? error.message : String(error);
  notify(message, "error");
  $("#outputBox").textContent = message;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
