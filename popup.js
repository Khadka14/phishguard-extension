// ==========================
// CONFIG (edit these later)
// ==========================
const CONFIG = {
  // A: Threat intel (e.g., VirusTotal domain API)
  // Sign up and put your API key here (or leave as-is to disable).
  virustotalApiKey: "PUT_YOUR_VIRUSTOTAL_API_KEY_HERE",

  // B: Domain age / WHOIS (e.g., api-ninjas.com, whoisxml, etc.)
  whoisApiKey: "PUT_YOUR_WHOIS_API_KEY_HERE",

  // C: Your own backend for AI scoring (DO NOT put OpenAI key in this file)
  // Example backend endpoint that you build yourself:
  // POST { url, findings } -> { aiComment, aiRisk }
  aiBackendUrl: "https://your-backend.example.com/ai-score"
};

// ==========================
// Base heuristic URL detector
// ==========================

const BRAND_DOMAINS = {
  "google.com": ["google", "gmail"],
  "facebook.com": ["facebook", "fb"],
  "paypal.com": ["paypal"],
  "apple.com": ["apple", "icloud"],
  "microsoft.com": ["microsoft", "office", "outlook"],
  "amazon.com": ["amazon"]
};

function evaluateUrl(rawUrl) {
  const reasons = [];
  let score = 0;

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (e) {
    reasons.push("Invalid URL format.");
    return { score: 100, level: "HIGH", reasons, hostname: null };
  }

  const protocol = parsed.protocol;
  const hostname = parsed.hostname.toLowerCase();
  const full = parsed.href;

  // 1. HTTP instead of HTTPS
  if (protocol === "http:") {
    score += 25;
    reasons.push("Connection is not secure (HTTP, not HTTPS).");
  }

  // 2. Host is an IP address instead of domain
  const ipRegex =
    /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]+$/i;
  if (ipRegex.test(hostname)) {
    score += 30;
    reasons.push("URL uses an IP address instead of a domain name.");
  }

  // 3. Suspiciously long hostname
  if (hostname.length > 35 && hostname.length <= 60) {
    score += 10;
    reasons.push("Domain name is unusually long.");
  } else if (hostname.length > 60) {
    score += 20;
    reasons.push("Domain name is extremely long (common in phishing).");
  }

  // 4. Many subdomains
  const labels = hostname.split(".");
  if (labels.length >= 4) {
    score += 10;
    reasons.push("Domain has many subdomains (possible obfuscation).");
  }

  // 5. Encoded or deceptive characters
  if (full.includes("@")) {
    score += 15;
    reasons.push("URL contains '@' which can hide the real destination.");
  }

  if ((full.match(/%/g) || []).length >= 3) {
    score += 10;
    reasons.push("URL is heavily encoded (may be hiding true destination).");
  }

  // 6. Brand impersonation
  for (const [officialDomain, keywords] of Object.entries(BRAND_DOMAINS)) {
    for (const keyword of keywords) {
      if (hostname.includes(keyword)) {
        if (!hostname.endsWith(officialDomain)) {
          score += 30;
          reasons.push(
            `Domain contains "${keyword}" but is not the official ${officialDomain} domain (possible impersonation).`
          );
        }
      }
    }
  }

  // Score limits
  score = Math.min(Math.max(score, 0), 100);

  let level;
  if (score >= 70) level = "HIGH";
  else if (score >= 35) level = "MEDIUM";
  else level = "LOW";

  if (reasons.length === 0) {
    reasons.push("No obvious phishing indicators found in the URL.");
  }

  return { score, level, reasons, hostname };
}

function updateMainUI(url, result) {
  const urlEl = document.getElementById("url");
  const scoreBox = document.getElementById("score-box");
  const scoreVal = document.getElementById("score-value");
  const riskLevelEl = document.getElementById("risk-level");
  const reasonsEl = document.getElementById("reasons");

  urlEl.textContent = url;
  scoreVal.textContent = result.score + "/100";
  reasonsEl.innerHTML = "";

  result.reasons.forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  });

  scoreBox.classList.remove("low", "medium", "high");

  if (result.level === "HIGH") {
    scoreBox.classList.add("high");
    riskLevelEl.textContent = "🚨 HIGH RISK – be careful!";
  } else if (result.level === "MEDIUM") {
    scoreBox.classList.add("medium");
    riskLevelEl.textContent = "⚠️ Medium risk – verify the site.";
  } else {
    scoreBox.classList.add("low");
    riskLevelEl.textContent = "✅ Low risk – no major issues found.";
  }
}

// ==========================
// Helpers
// ==========================

function getActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0]);
    });
  });
}

// ==========================
// A: Threat Intel Check
// ==========================

async function checkThreatIntel(hostname) {
  const el = document.getElementById("threat-intel-status");

  if (!hostname) {
    el.textContent = "Cannot check threat intel: invalid hostname.";
    return { scoreBonus: 0, reason: null };
  }

  if (
    !CONFIG.virustotalApiKey ||
    CONFIG.virustotalApiKey.startsWith("PUT_")
  ) {
    el.textContent = "(Threat intel not configured – add API key in popup.js CONFIG.)";
    return { scoreBonus: 0, reason: null };
  }

  try {
    el.textContent = "Checking threat intel…";

    // Example: VirusTotal domain report endpoint
    const resp = await fetch(
      "https://www.virustotal.com/api/v3/domains/" +
        encodeURIComponent(hostname),
      {
        headers: {
          "x-apikey": CONFIG.virustotalApiKey
        }
      }
    );

    if (!resp.ok) {
      el.textContent = `Threat intel API error (status ${resp.status}).`;
      return { scoreBonus: 0, reason: null };
    }

    const data = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    if (malicious > 0 || suspicious > 0) {
      const engines = malicious + suspicious;
      el.textContent = `⚠️ Marked suspicious/malicious by ${engines} engine(s) in threat intel.`;
      const reason = `Threat intel: flagged by ${engines} security engine(s).`;
      const bonus = engines >= 3 ? 35 : 20;
      return { scoreBonus: bonus, reason };
    } else {
      el.textContent = "✅ Not flagged by threat intel sources (at time of check).";
      return { scoreBonus: 0, reason: "Threat intel: not currently flagged." };
    }
  } catch (err) {
    console.error("Threat intel error", err);
    el.textContent = "Threat intel check failed (network or CORS issue).";
    return { scoreBonus: 0, reason: null };
  }
}

// ==========================
// B: Domain Age / WHOIS Check
// ==========================

async function checkDomainAge(hostname) {
  const el = document.getElementById("domain-age-status");

  if (!hostname) {
    el.textContent = "Cannot check domain age: invalid hostname.";
    return { scoreBonus: 0, reason: null };
  }

  if (!CONFIG.whoisApiKey || CONFIG.whoisApiKey.startsWith("PUT_")) {
    el.textContent = "(Domain age not configured – add WHOIS API key in popup.js CONFIG.)";
    return { scoreBonus: 0, reason: null };
  }

  try {
    el.textContent = "Checking domain age…";

    // Example WHOIS API (you must pick a real provider and adapt this)
    // Here we assume: GET https://api.api-ninjas.com/v1/whois?domain=example.com
    const resp = await fetch(
      "https://api.api-ninjas.com/v1/whois?domain=" +
        encodeURIComponent(hostname),
      {
        headers: {
          "X-Api-Key": CONFIG.whoisApiKey
        }
      }
    );

    if (!resp.ok) {
      el.textContent = `WHOIS API error (status ${resp.status}).`;
      return { scoreBonus: 0, reason: null };
    }

    const data = await resp.json();

    const created =
      data.creation_date || data.created || data.registered_on || null;

    if (!created) {
      el.textContent = "Could not determine domain creation date.";
      return { scoreBonus: 0, reason: null };
    }

    const createdDate = new Date(created);
    const ageMs = Date.now() - createdDate.getTime();
    const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));

    let msg = `Domain appears to be about ${ageDays} day(s) old. `;
    let bonus = 0;

    if (ageDays < 30) {
      msg += "🚨 Very new domain – often used in phishing.";
      bonus = 25;
    } else if (ageDays < 90) {
      msg += "⚠️ Relatively new domain – treat with caution.";
      bonus = 15;
    } else {
      msg += "✅ Domain is older than 90 days.";
      bonus = 0;
    }

    el.textContent = msg;
    return { scoreBonus: bonus, reason: msg };
  } catch (err) {
    console.error("WHOIS error", err);
    el.textContent = "Domain age check failed (network or CORS issue).";
    return { scoreBonus: 0, reason: null };
  }
}

// ==========================
// C: AI Risk Review (backend-based)
// ==========================

async function runAiReview(url, findings) {
  const el = document.getElementById("ai-status");

  if (
    !CONFIG.aiBackendUrl ||
    CONFIG.aiBackendUrl.includes("your-backend.example.com")
  ) {
    el.textContent =
      "(AI review not configured – set aiBackendUrl in popup.js to your own backend. Do NOT put your OpenAI key in the extension.)";
    return;
  }

  try {
    el.textContent = "Contacting AI backend…";

    const resp = await fetch(CONFIG.aiBackendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url, findings })
    });

    if (!resp.ok) {
      el.textContent = `AI backend error (status ${resp.status}).`;
      return;
    }

    const data = await resp.json();
    const aiComment = data.aiComment || "AI did not return a comment.";
    const aiRisk = data.aiRisk || "UNKNOWN";

    el.textContent = `AI risk: ${aiRisk}. ${aiComment}`;
  } catch (err) {
    console.error("AI backend error", err);
    el.textContent = "AI review failed (backend not reachable).";
  }
}

// ==========================
// Main orchestration
// ==========================

async function runFullAnalysis() {
  const tab = await getActiveTab();
  if (!tab || !tab.url) {
    updateMainUI("No active tab URL found.", {
      score: 0,
      level: "LOW",
      reasons: ["Could not read the active tab URL."]
    });
    return;
  }

  const baseResult = evaluateUrl(tab.url);
  let combinedReasons = [...baseResult.reasons];
  let combinedScore = baseResult.score;

  updateMainUI(tab.url, baseResult);

  // Run threat intel and WHOIS checks in parallel
  const [intelResult, whoisResult] = await Promise.all([
    checkThreatIntel(baseResult.hostname),
    checkDomainAge(baseResult.hostname)
  ]);

  if (intelResult?.reason) {
    combinedReasons.push(intelResult.reason);
    combinedScore = Math.min(100, combinedScore + intelResult.scoreBonus);
  }

  if (whoisResult?.reason) {
    combinedReasons.push(whoisResult.reason);
    combinedScore = Math.min(100, combinedScore + whoisResult.scoreBonus);
  }

  // Recalculate level based on updated score
  let level;
  if (combinedScore >= 70) level = "HIGH";
  else if (combinedScore >= 35) level = "MEDIUM";
  else level = "LOW";

  const finalResult = {
    score: combinedScore,
    level,
    reasons: combinedReasons
  };

  updateMainUI(tab.url, finalResult);

  // Store last findings for AI button
  window.__phishguardLast = {
    url: tab.url,
    findings: finalResult
  };
}

// ==========================
// Event wiring
// ==========================

document.addEventListener("DOMContentLoaded", () => {
  runFullAnalysis();

  document
    .getElementById("recheck")
    .addEventListener("click", () => runFullAnalysis());

  document
    .getElementById("ai-review")
    .addEventListener("click", () => {
      const last = window.__phishguardLast;
      if (!last) {
        document.getElementById("ai-status").textContent =
          "Run a scan first before asking AI.";
        return;
      }
      runAiReview(last.url, last.findings);
    });
});
