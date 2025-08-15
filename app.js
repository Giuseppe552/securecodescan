// ---------- tiny helper ----------
const $ = (sel) => document.querySelector(sel)
const codeEl = $("#code")
const langEl = $("#language")
const riskEl = $("#risk")
const fillEl = $("#meterFill")
const findingsEl = $("#findings")
const analyzeBtn = $("#analyze")
const clearBtn = $("#clear")
const downloadBtn = $("#download")

// ---------- heuristics (regex rules) ----------
/**
 * Each rule: { id, title, severity, languages, pattern, explain, fix }
 * severity: low=10, medium=25, high=40 points
 */
const RULES = [
  // ===== XSS / DOM sinks =====
  {
    id: "xss-innerhtml",
    title: "Potential XSS via innerHTML",
    severity: "high",
    languages: ["javascript","html","auto"],
    pattern: /\binnerHTML\s*=/i,
    explain: "Assigning to innerHTML with untrusted data can execute scripts.",
    fix: "Use textContent or safe templating instead; sanitize with a vetted library."
  },
  {
    id: "xss-inline-handler",
    title: "Inline event handler (onclick= etc.)",
    severity: "medium",
    languages: ["html","auto"],
    pattern: /\son\w+\s*=/i,
    explain: "Inline handlers are hard to audit and enable injection.",
    fix: "Attach events in JS (addEventListener) and sanitize attributes."
  },
  {
    id: "xss-unsafe-url",
    title: "Dangerous URL insertion into DOM",
    severity: "medium",
    languages: ["javascript","auto"],
    pattern: /\.(innerHTML|outerHTML)\s*=\s*.*(location|document\.URL|search|hash)/i,
    explain: "Using location-derived values in HTML can lead to reflected XSS.",
    fix: "Parse and validate URL params; never write them into HTML directly."
  },

  // ===== Dangerous JS =====
  {
    id: "js-eval",
    title: "Use of eval / Function constructor",
    severity: "high",
    languages: ["javascript","auto"],
    pattern: /\b(eval|Function)\s*\(/,
    explain: "Dynamic code execution is a code-injection sink.",
    fix: "Avoid eval; use JSON.parse or explicit dispatch maps instead."
  },

  // ===== SQL Injection =====
  {
    id: "sqli-py",
    title: "String-built SQL query (Python)",
    severity: "high",
    languages: ["python","auto"],
    pattern: /(cursor\.execute\(\s*f?["'`].*SELECT.*\+|%s|\{)/is,
    explain: "Building SQL with string concat/format enables injection.",
    fix: "Use parameterized queries (e.g., psycopg2 execute with params tuple)."
  },
  {
    id: "sqli-php",
    title: "String-built SQL query (PHP/JS)",
    severity: "high",
    languages: ["php","javascript","sql","auto"],
    pattern: /(SELECT|INSERT|UPDATE|DELETE)[^;]*\+|\.query\(\s*["'`].*(SELECT|INSERT|UPDATE|DELETE)/is,
    explain: "Concatenating user input into SQL risks injection.",
    fix: "Use prepared statements / placeholders with your DB client."
  },

  // ===== Secrets / keys =====
  {
    id: "secret-api",
    title: "Hardcoded credential / API key",
    severity: "high",
    languages: ["javascript","python","php","auto"],
    pattern: /(api[_-]?key|secret|authorization|bearer)[^A-Za-z0-9]?["'][A-Za-z0-9_\-]{16,}["']/i,
    explain: "Looks like a token or credential embedded in code.",
    fix: "Move secrets to environment variables or a secrets manager."
  },

  // ===== Crypto =====
  {
    id: "crypto-weak-hash",
    title: "Weak hash function (MD5/SHA1)",
    severity: "medium",
    languages: ["javascript","python","php","auto"],
    pattern: /\b(md5|sha1)\b/i,
    explain: "MD5/SHA1 are collision-prone and not for security.",
    fix: "Use SHA-256/512 or a password hashing function (bcrypt/Argon2)."
  },
  {
    id: "crypto-ecb",
    title: "AES ECB mode detected",
    severity: "medium",
    languages: ["python","php","javascript","auto"],
    pattern: /\bECB\b/,
    explain: "ECB mode leaks patterns and is insecure.",
    fix: "Use GCM/CTR/CBC with random IV; prefer libs with high-level APIs."
  },

  // ===== Mixed content / cleartext =====
  {
    id: "insecure-http",
    title: "HTTP (non-TLS) requested",
    severity: "medium",
    languages: ["javascript","html","auto"],
    pattern: /http:\/\/[^\s'"]+/i,
    explain: "Requests over HTTP can be intercepted/modified.",
    fix: "Use HTTPS endpoints; enable HSTS and secure cookies."
  }
]

// map severity to weight
const SCORE = { low: 10, medium: 25, high: 40 }

// naive language auto-detect
function detectLanguage(src) {
  const s = src.slice(0, 400).toLowerCase()
  if (s.includes("<html") || s.includes("</div>")) return "html"
  if (s.includes("<?php") || s.includes("->query(")) return "php"
  if (s.includes("import ") || s.includes("def ")) return "python"
  if (s.includes("function ") || s.includes("const ") || s.includes("=>")) return "javascript"
  if (s.match(/\bselect\b.*\bfrom\b/)) return "sql"
  return "auto"
}

// run analysis
function analyze() {
  const src = codeEl.value || ""
  const chosen = langEl.value
  const lang = chosen === "auto" ? detectLanguage(src) : chosen

  // split lines for simple line refs
  const lines = src.split(/\r?\n/)
  const matches = []

  for (const rule of RULES) {
    if (!rule.languages.includes("auto") && !rule.languages.includes(lang)) continue
    const re = new RegExp(rule.pattern, rule.pattern.flags || "i")
    let m
    // scan each line to attach line numbers
    lines.forEach((line, i) => {
      if (re.test(line)) {
        matches.push({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          line: i + 1,
          snippet: line.trim().slice(0, 180),
          explain: rule.explain,
          fix: rule.fix
        })
      }
    })
  }

  // compute score (cap 100)
  const total = Math.min(
    matches.reduce((sum, x) => sum + SCORE[x.severity], 0),
    100
  )

  // render
  riskEl.textContent = `${total}/100`
  fillEl.style.width = `${total}%`

  findingsEl.innerHTML = ""
  if (!matches.length) {
    findingsEl.innerHTML = `<li class="sev-low"><strong>No obvious issues found.</strong> This is a heuristic scan — not a guarantee. Consider a full SAST/DAST run.</li>`
  } else {
    for (const f of matches) {
      const li = document.createElement("li")
      li.className = `sev-${f.severity.startsWith("h") ? "high" : f.severity.startsWith("m") ? "med" : "low"}`
      li.innerHTML = `
        <div><strong>${escapeHtml(f.title)}</strong> <span class="path">— line ${f.line}</span></div>
        <div><code>${escapeHtml(f.snippet)}</code></div>
        <div>${escapeHtml(f.explain)}</div>
        <div><em>Fix:</em> ${escapeHtml(f.fix)}</div>
      `
      findingsEl.appendChild(li)
    }
  }

  // stash for download
  window.__scanReport = { score: total, lang, matches, generatedAt: new Date().toISOString() }
}

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]))
}

// download JSON report
function downloadReport() {
  const report = window.__scanReport || { note: "Run an analysis first." }
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `securecodescan-report-${Date.now()}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// events
analyzeBtn.addEventListener("click", analyze)
clearBtn.addEventListener("click", () => { codeEl.value = ""; findingsEl.innerHTML = ""; riskEl.textContent = "0/100"; fillEl.style.width = "0%" })
downloadBtn.addEventListener("click", downloadReport)
