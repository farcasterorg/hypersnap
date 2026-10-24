// Retro Rewards Report — vanilla-JS SPA
//
// Views (hash-routed):
//   #/                 — rankings index
//   #/combo/<id>       — full ranking for a single ranking id
//   #/fid              — FID lookup prompt
//   #/fid/<fid>        — FID trajectory across all rankings
//   #/impact           — feature impact (ablation)
//   #/similarity       — Spearman similarity heatmap

const DATA_DIR = "data";

// Must match TRAJECTORY_SHARDS in retro_rewards_report.rs.
const TRAJECTORY_SHARDS = 1024;

// --- module-level caches (populated lazily) ---
const cache = {
  index: null,                   // rankings_index.json
  rankings: new Map(),           // id → { id, label, entries: [[fid, tokens], ...] }
  trajectoryShards: new Map(),   // shardId → { fidStr: [[idx, rank, tokens]...] }
  impact: null,                  // feature_impact.json
  similarity: null,              // similarity.json
};

// --- entry ---
const app = document.getElementById("app");
window.addEventListener("hashchange", route);
window.addEventListener("load", route);

async function route() {
  const hash = (location.hash || "").slice(1) || "/";
  const parts = hash.split("/").filter(Boolean);
  setLoading();
  try {
    if (parts.length === 0) {
      await viewIndex();
    } else if (parts[0] === "combo") {
      await viewCombo(parts[1] ?? "baseline");
    } else if (parts[0] === "fid") {
      await viewFid(parts[1] ?? null);
    } else if (parts[0] === "impact") {
      await viewImpact();
    } else if (parts[0] === "similarity") {
      await viewSimilarity();
    } else {
      showError(`Unknown path: ${hash}`);
    }
  } catch (err) {
    console.error(err);
    showError(err.message || String(err));
  }
}

function setLoading(msg = "Loading…") {
  app.innerHTML = `<p class="loading">${escapeHtml(msg)}</p>`;
}

function showError(msg) {
  app.innerHTML = `<p class="error">${escapeHtml(msg)}</p>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

async function fetchJson(path) {
  const res = await fetch(`${DATA_DIR}/${path}`);
  if (!res.ok) throw new Error(`Failed to load ${path}: ${res.status}`);
  return res.json();
}

async function loadIndex() {
  if (cache.index) return cache.index;
  cache.index = await fetchJson("rankings_index.json");
  return cache.index;
}

async function loadRanking(id) {
  if (cache.rankings.has(id)) return cache.rankings.get(id);
  const data = await fetchJson(`rankings/${id}.json`);
  cache.rankings.set(id, data);
  return data;
}

// Load just the shard containing this FID's trajectory, caching by shard id.
// A shard is ~1-2 MB; once loaded, lookups within the same shard are instant.
async function loadFidTrajectory(fid) {
  const shardId = Number(fid) % TRAJECTORY_SHARDS;
  let shard = cache.trajectoryShards.get(shardId);
  if (!shard) {
    const name = String(shardId).padStart(4, "0");
    shard = await fetchJson(`fid_trajectories/shard_${name}.json`);
    cache.trajectoryShards.set(shardId, shard);
  }
  return shard[String(fid)] || [];
}

async function loadImpact() {
  if (cache.impact) return cache.impact;
  cache.impact = await fetchJson("feature_impact.json");
  return cache.impact;
}

async function loadSimilarity() {
  if (cache.similarity) return cache.similarity;
  cache.similarity = await fetchJson("similarity.json");
  return cache.similarity;
}

// ========== VIEW: Rankings index ==========

async function viewIndex() {
  const idx = await loadIndex();
  document.title = "Rankings — Retro Rewards Report";

  const rows = idx.rankings
    .map((r) => {
      const feats = (r.features || [])
        .map((f) => `<span class="badge">${f}</span>`)
        .join("");
      return `<tr data-id="${escapeHtml(r.id)}">
        <td class="fid">${escapeHtml(r.id)}</td>
        <td>${escapeHtml(r.source)}</td>
        <td class="features-label">${escapeHtml(r.label || "")}</td>
        <td>${feats}</td>
        <td class="numeric">${r.non_zero_count.toLocaleString()}</td>
        <td class="fid">${r.top_fid ? r.top_fid.toLocaleString() : "—"}</td>
      </tr>`;
    })
    .join("");

  app.innerHTML = `
    <h2>Rankings (${idx.rankings.length})</h2>
    <p class="subtitle">Original baseline, three <code>retro_rewards_new</code> modes, and 127 combo toggles. Click a row to see the full ranking.</p>
    <table class="rankings-index">
      <thead>
        <tr>
          <th>ID</th>
          <th>Source</th>
          <th>Label</th>
          <th>Features</th>
          <th># nonzero FIDs</th>
          <th>Top FID</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;

  app.querySelectorAll("tbody tr").forEach((tr) => {
    tr.addEventListener("click", () => {
      location.hash = `#/combo/${tr.dataset.id}`;
    });
  });
}

// ========== VIEW: Single combination (full ranking, virtual-scrolled) ==========

async function viewCombo(id) {
  const [idx, ranking] = await Promise.all([loadIndex(), loadRanking(id)]);
  const meta = idx.rankings.find((r) => r.id === id);
  document.title = `${id} — Retro Rewards Report`;

  const entries = ranking.entries; // [[fid, tokens], ...] sorted by tokens desc
  const totalTokens = entries.reduce((s, e) => s + e[1], 0);

  const shell = document.createElement("div");
  shell.innerHTML = `
    <a class="back-link" href="#/">← All rankings</a>
    <h2>${escapeHtml(id)}</h2>
    <div class="meta">
      <dl>
        <dt>Source</dt><dd>${escapeHtml(meta?.source || "?")}</dd>
        <dt>Label</dt><dd>${escapeHtml(meta?.label || "—")}</dd>
        <dt>Features</dt><dd>${(meta?.features || []).join(", ") || "—"}</dd>
        <dt># nonzero</dt><dd>${entries.length.toLocaleString()}</dd>
        <dt>Pool total</dt><dd>${formatTokens(totalTokens)}</dd>
      </dl>
    </div>
    <div class="toolbar">
      <strong>All ${entries.length.toLocaleString()} FIDs</strong>
      <input class="search-input" type="text" placeholder="Filter by FID…">
    </div>
    <div class="virtual-scroll" id="vs">
      <div class="spacer"></div>
    </div>
  `;
  app.replaceChildren(shell);

  let filtered = entries;
  const search = shell.querySelector("input.search-input");
  const vs = shell.querySelector("#vs");

  const setup = setupVirtualScroll(vs, {
    rowHeight: 28,
    getTotal: () => filtered.length,
    renderRows: (start, end) => {
      const out = [];
      out.push(`<table><thead><tr><th style="width:80px">Rank</th><th style="width:160px">FID</th><th style="width:180px" class="numeric">Tokens</th><th class="numeric">Share %</th></tr></thead><tbody>`);
      for (let i = start; i < end; i++) {
        const [fid, tokens] = filtered[i];
        const share = totalTokens > 0 ? (tokens / totalTokens * 100) : 0;
        out.push(`<tr>
          <td class="numeric">${(i + 1).toLocaleString()}</td>
          <td class="fid"><a href="#/fid/${fid}">${fid.toLocaleString()}</a></td>
          <td class="numeric">${formatTokens(tokens)}</td>
          <td class="numeric">${share.toFixed(4)}%</td>
        </tr>`);
      }
      out.push("</tbody></table>");
      return out.join("");
    },
  });

  search.addEventListener("input", () => {
    const q = search.value.trim();
    if (!q) {
      filtered = entries;
    } else {
      const needle = q;
      filtered = entries.filter(([fid]) => String(fid).includes(needle));
    }
    setup.refresh();
  });

  setup.refresh();
}

// ========== VIEW: FID trajectory ==========

async function viewFid(fid) {
  if (!fid) {
    // No FID in URL — show the search prompt.
    app.innerHTML = `
      <h2>FID lookup</h2>
      <p class="subtitle">Enter a FID to see its rank and token allocation across all rankings.</p>
      <div class="trajectory-input">
        <input type="text" id="fid-input" placeholder="FID (e.g. 12345)">
        <button id="fid-go">Look up</button>
      </div>
    `;
    const go = () => {
      const v = document.getElementById("fid-input").value.trim();
      if (v) location.hash = `#/fid/${v}`;
    };
    document.getElementById("fid-go").addEventListener("click", go);
    document.getElementById("fid-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") go();
    });
    document.getElementById("fid-input").focus();
    return;
  }

  const idx = await loadIndex();
  const entries = await loadFidTrajectory(fid);

  // Build a full table including rankings where this FID scored 0.
  const byIdx = new Map(entries.map((e) => [e[0], e]));
  const rows = idx.rankings.map((meta, i) => {
    const rec = byIdx.get(i);
    const rank = rec ? rec[1] : null;
    const tokens = rec ? rec[2] : 0;
    return {
      id: meta.id,
      source: meta.source || "",
      label: meta.label || "",
      rank,
      tokens,
    };
  });

  document.title = `FID ${fid} — Retro Rewards Report`;

  const nonZero = rows.filter((r) => r.tokens > 0);
  let bestRank = nonZero.length ? Math.min(...nonZero.map((r) => r.rank)) : null;
  let worstRank = nonZero.length ? Math.max(...nonZero.map((r) => r.rank)) : null;

  const shell = document.createElement("div");
  shell.innerHTML = `
    <a class="back-link" href="#/fid">← FID lookup</a>
    <h2>FID ${escapeHtml(fid)}</h2>
    <div class="meta">
      <dl>
        <dt>Rankings with allocation</dt><dd>${nonZero.length} / ${rows.length}</dd>
        <dt>Best rank</dt><dd>${bestRank ?? "—"}</dd>
        <dt>Worst rank</dt><dd>${worstRank ?? "—"}</dd>
      </dl>
    </div>
    <div class="toolbar">
      <strong>Across all rankings</strong>
      <input class="search-input" type="text" placeholder="Filter by ranking id…">
    </div>
    <div class="virtual-scroll" id="vs-fid">
      <div class="spacer"></div>
    </div>
  `;
  app.replaceChildren(shell);

  let filtered = rows;
  const search = shell.querySelector("input.search-input");
  const vs = shell.querySelector("#vs-fid");

  const setup = setupVirtualScroll(vs, {
    rowHeight: 28,
    getTotal: () => filtered.length,
    renderRows: (start, end) => {
      const out = [];
      out.push(`<table><thead><tr><th style="width:120px">Ranking</th><th style="width:120px">Source</th><th style="width:140px" class="features-label">Label</th><th style="width:80px" class="numeric">Rank</th><th class="numeric">Tokens</th></tr></thead><tbody>`);
      for (let i = start; i < end; i++) {
        const r = filtered[i];
        out.push(`<tr>
          <td class="fid"><a href="#/combo/${r.id}">${escapeHtml(r.id)}</a></td>
          <td>${escapeHtml(r.source)}</td>
          <td class="features-label">${escapeHtml(r.label)}</td>
          <td class="numeric">${r.rank != null ? r.rank.toLocaleString() : "—"}</td>
          <td class="numeric">${r.tokens > 0 ? formatTokens(r.tokens) : "—"}</td>
        </tr>`);
      }
      out.push("</tbody></table>");
      return out.join("");
    },
  });

  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    filtered = q ? rows.filter((r) => r.id.toLowerCase().includes(q) || r.label.toLowerCase().includes(q)) : rows;
    setup.refresh();
  });

  setup.refresh();
}

// ========== VIEW: Feature impact ==========

async function viewImpact() {
  const impact = await loadImpact();
  document.title = "Feature impact — Retro Rewards Report";

  const cards = impact.features
    .map((f) => {
      const helps = (f.helps || [])
        .slice(0, 20)
        .map(
          (e) =>
            `<tr>
              <td class="fid"><a href="#/fid/${e.fid}">${e.fid.toLocaleString()}</a></td>
              <td class="numeric delta-pos">${e.delta.toFixed(2)}</td>
            </tr>`
        )
        .join("");
      const hurts = (f.hurts || [])
        .slice(0, 20)
        .map(
          (e) =>
            `<tr>
              <td class="fid"><a href="#/fid/${e.fid}">${e.fid.toLocaleString()}</a></td>
              <td class="numeric delta-neg">${e.delta.toFixed(2)}</td>
            </tr>`
        )
        .join("");
      return `
        <div class="impact-card">
          <h3>${f.id}. ${escapeHtml(f.name)}</h3>
          <p class="subtitle">Mean token delta per FID when this feature is ON vs OFF, across the 64 paired combinations.</p>
          <h3 style="margin-top:12px">Most helped (feature on → higher tokens)</h3>
          <table><thead><tr><th>FID</th><th class="numeric">Δ tokens</th></tr></thead><tbody>${helps}</tbody></table>
          <h3>Most hurt (feature on → lower tokens)</h3>
          <table><thead><tr><th>FID</th><th class="numeric">Δ tokens</th></tr></thead><tbody>${hurts}</tbody></table>
        </div>
      `;
    })
    .join("");

  app.innerHTML = `
    <h2>Feature impact</h2>
    <p class="subtitle">For each of the 7 toggleable features, the FIDs whose token allocation moves most when the feature is flipped on. Computed across the 64 paired combinations (feature on vs feature off, all other features held constant).</p>
    <div class="impact-grid">${cards}</div>
  `;
}

// ========== VIEW: Similarity heatmap ==========

async function viewSimilarity() {
  const sim = await loadSimilarity();
  document.title = "Similarity — Retro Rewards Report";

  const n = sim.rankings.length;
  const cellSize = Math.max(3, Math.min(8, Math.floor(800 / n)));

  app.innerHTML = `
    <h2>Similarity heatmap</h2>
    <p class="subtitle">Spearman rank correlation between each pair of rankings, computed on the top-5000 FIDs of each. Bright colors = similar rankings. Blocks of similar rankings suggest combinations that produce the same ordering.</p>
    <div class="heatmap" id="hm">
      <canvas width="${n * cellSize}" height="${n * cellSize}"></canvas>
    </div>
    <div class="heatmap-legend">
      <span>−1 (opposite)</span>
      <canvas id="hm-legend" width="120" height="10"></canvas>
      <span>+1 (identical)</span>
    </div>
    <div id="hm-tip" class="heatmap-tooltip"></div>
  `;

  const canvas = document.querySelector("#hm canvas");
  const ctx = canvas.getContext("2d");
  const mat = sim.matrix;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      ctx.fillStyle = heatColor(mat[i][j]);
      ctx.fillRect(j * cellSize, i * cellSize, cellSize, cellSize);
    }
  }

  const legend = document.querySelector("#hm-legend");
  const lctx = legend.getContext("2d");
  for (let x = 0; x < legend.width; x++) {
    const v = (x / (legend.width - 1)) * 2 - 1;
    lctx.fillStyle = heatColor(v);
    lctx.fillRect(x, 0, 1, legend.height);
  }

  const tip = document.getElementById("hm-tip");
  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const j = Math.floor((e.clientX - rect.left) / cellSize);
    const i = Math.floor((e.clientY - rect.top) / cellSize);
    if (i < 0 || i >= n || j < 0 || j >= n) {
      tip.style.display = "none";
      return;
    }
    const v = mat[i][j];
    tip.textContent = `${sim.rankings[i]} ↔ ${sim.rankings[j]}: ρ = ${v.toFixed(3)}`;
    tip.style.display = "block";
    tip.style.left = e.clientX + 12 + "px";
    tip.style.top = e.clientY + 12 + "px";
  });
  canvas.addEventListener("mouseleave", () => {
    tip.style.display = "none";
  });
}

// ========== Utilities ==========

function heatColor(v) {
  // v ∈ [-1, 1]. -1 → blue (70,100,200), 0 → white, +1 → red-orange (220,80,60).
  const x = Math.max(-1, Math.min(1, v));
  if (x >= 0) {
    const t = x;
    const r = Math.round(255 * (1 - 0.14 * t));
    const g = Math.round(255 * (1 - 0.69 * t));
    const b = Math.round(255 * (1 - 0.76 * t));
    return `rgb(${r},${g},${b})`;
  } else {
    const t = -x;
    const r = Math.round(255 * (1 - 0.73 * t));
    const g = Math.round(255 * (1 - 0.61 * t));
    const b = Math.round(255 * (1 - 0.22 * t));
    return `rgb(${r},${g},${b})`;
  }
}

function formatTokens(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(2) + "K";
  return n.toFixed(2);
}

// Simple virtual-scroll component.
function setupVirtualScroll(container, opts) {
  const { rowHeight, getTotal, renderRows } = opts;
  const spacer = container.querySelector(".spacer");

  const render = () => {
    const total = getTotal();
    spacer.style.height = `${total * rowHeight + 30}px`; // +30 for thead

    const scrollTop = container.scrollTop;
    const viewport = container.clientHeight;
    const buffer = 20;
    const start = Math.max(0, Math.floor((scrollTop - 30) / rowHeight) - buffer);
    const end = Math.min(total, start + Math.ceil(viewport / rowHeight) + 2 * buffer);

    const existing = spacer.querySelector("table");
    if (existing) existing.remove();

    const html = renderRows(start, end);
    const wrapper = document.createElement("div");
    wrapper.innerHTML = html;
    const table = wrapper.querySelector("table");
    if (table) {
      table.style.top = `${start * rowHeight}px`;
      spacer.appendChild(table);
    }
  };

  container.addEventListener("scroll", () => requestAnimationFrame(render));
  window.addEventListener("resize", () => requestAnimationFrame(render));

  return { refresh: render };
}
