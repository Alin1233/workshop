// Page de consultation de l'assistant : tout le contenu reçu est inséré en texte (textContent), jamais en HTML.
"use strict";

const $ = (id) => document.getElementById(id);

// Cette méthode permet d'afficher l'état de l'assistant (Ollama, modèles, index) à partir de /health.
async function refreshStatus() {
  const el = $("status");
  try {
    const res = await fetch("/health", { cache: "no-store" });
    const body = await res.json();
    const o = body.checks.ollama, idx = body.checks.index;
    if (body.status === "ok") {
      el.textContent = `Opérationnel — modèle ${o.llm_model}, ${idx.chunks} extraits de ${idx.documents.length} documents indexés`;
      el.className = "status ok";
    } else {
      const reasons = [];
      if (!o.reachable) reasons.push(`Ollama injoignable (${o.url})`);
      else if (!o.llm_available || !o.embed_available) reasons.push("modèle non installé dans Ollama");
      if (idx.state !== "ready") reasons.push(`index : ${idx.state}`);
      el.textContent = `Mode dégradé — ${reasons.join(", ")}`;
      el.className = "status degraded";
    }
  } catch (err) {
    el.textContent = "Assistant injoignable";
    el.className = "status degraded";
  }
}

// Cette méthode permet d'afficher la réponse en mettant en évidence les renvois [n] vers les sources.
function renderAnswer(text) {
  const box = $("answer");
  box.replaceChildren();
  for (const part of text.split(/(\[[^\]]{1,20}\])/)) {
    const span = document.createElement("span");
    span.textContent = part;
    if (/^\[[^\]]+\]$/.test(part)) span.className = "cite";
    box.appendChild(span);
  }
}

// Cette méthode permet de lister les extraits utilisés, cités d'abord, avec fichier, section et score de similarité.
function renderSources(sources) {
  const list = $("sources");
  list.replaceChildren();
  const ordered = [...sources].sort((a, b) => Number(b.cited) - Number(a.cited) || a.id - b.id);
  for (const s of ordered) {
    const li = document.createElement("li");
    li.value = s.id;
    if (!s.cited) li.className = "uncited";
    const file = document.createElement("span");
    file.className = "file";
    file.textContent = s.source;
    li.append(file, ` — ${s.section} (score ${s.score.toFixed(2)}${s.cited ? ", cité" : ", consulté"})`);
    li.title = s.excerpt;
    list.appendChild(li);
  }
  if (!sources.length) list.textContent = "Aucun extrait pertinent.";
}

// Cette méthode permet de rappeler les alertes actives qui ont servi de contexte à la réponse.
function renderAlerts(alerts, error) {
  const list = $("alerts");
  list.replaceChildren();
  for (const a of alerts) {
    const li = document.createElement("li");
    li.textContent = `${a.name} (${a.severity || "?"}, ${a.service || "?"}) — ${a.summary}`;
    list.appendChild(li);
  }
  if (error) {
    const li = document.createElement("li");
    li.textContent = "Alertmanager injoignable : réponse sans contexte d'alertes.";
    list.appendChild(li);
  }
  $("alerts-block").hidden = !alerts.length && !error;
}

$("ask-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const question = $("question").value.trim();
  if (question.length < 3) return;
  $("submit").disabled = true;
  $("submit").textContent = "Recherche…";
  $("error").hidden = true;
  try {
    const res = await fetch("/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, include_alerts: $("include-alerts").checked }),
    });
    const body = await res.json();
    if (!res.ok) {
      // 422 : FastAPI renvoie la liste des erreurs de validation ; les autres erreurs ont un « detail » textuel.
      const detail = typeof body.detail === "string" ? body.detail : "Question invalide (3 à 500 caractères)";
      throw new Error(detail);
    }
    renderAnswer(body.answer);
    renderSources(body.sources);
    renderAlerts(body.alerts, body.alerts_error);
    const seconds = (body.timings_ms.retrieval + body.timings_ms.generation) / 1000;
    $("meta").textContent = `— ${body.model}, ${seconds.toFixed(1)} s${body.refused ? ", hors documentation" : ""}`;
    $("result").hidden = false;
  } catch (err) {
    $("error").textContent = typeof err.message === "string" ? err.message : "Erreur inattendue";
    $("error").hidden = false;
  } finally {
    $("submit").disabled = false;
    $("submit").textContent = "Demander";
    refreshStatus();
  }
});

refreshStatus();
setInterval(refreshStatus, 30000);
