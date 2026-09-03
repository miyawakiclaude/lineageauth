/* FLOP Activity Console.
 *
 * Two rules run through every line of this file.
 *
 * 1. No string ever becomes markup. Every value shown here -- activity
 *    titles, prompts, room and rule text, source notes -- was written by
 *    somebody else, or is untrusted text a viewer pasted into the safety
 *    scanner. Text reaches the page through textContent and through nothing
 *    else; a test reads this file and fails on any construct that could turn
 *    a string into markup.
 *
 * 2. This page verifies nothing and asserts no eligibility. It renders what
 *    the local, read-only API already computed, and every screen that could
 *    be mistaken for a promise repeats that it is not one.
 */

/* ------------------------------------------------------------ dom helpers */

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null && text !== "") {
    node.textContent = String(text);
  }
  if (className) {
    node.className = className;
  }
  return node;
}

function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function announce(text) {
  const region = document.getElementById("live-region");
  if (region) {
    region.textContent = text;
  }
}

function pairs(entries) {
  const list = document.createElement("dl");
  list.className = "pairs";
  for (const [key, value] of entries) {
    list.appendChild(el("dt", key));
    const shown = value === null || value === undefined || value === "" ? "--" : value;
    list.appendChild(el("dd", shown));
  }
  return list;
}

function card(title) {
  const box = el("div", null, "card");
  if (title) {
    box.appendChild(el("h3", title));
  }
  return box;
}

function note(text) {
  return el("p", text, "note");
}

function problem(where, message) {
  clear(where);
  where.appendChild(el("p", message, "note"));
}

function rawJson(value) {
  const details = document.createElement("details");
  details.appendChild(el("summary", "Raw response"));
  details.appendChild(el("pre", JSON.stringify(value, null, 2)));
  return details;
}

/* --------------------------------------------------------------- badges */

function sourceBadge(sourceClass) {
  const label = String(sourceClass || "unknown").toUpperCase().replace(/-/g, " ");
  return el("span", label, "badge badge-source-" + String(sourceClass || "unknown"));
}

function evidenceBadge(level) {
  const label = String(level || "self-claimed").toUpperCase().replace(/-/g, " ");
  return el("span", label, "badge badge-evidence-" + String(level || "self-claimed"));
}

function safetyBadge(level, display) {
  const key = String(level || "INFO").toLowerCase();
  return el("span", display || level, "badge badge-safety-" + key);
}

function syntheticBadge() {
  return el("span", "SYNTHETIC MOCK DATA", "badge badge-synthetic");
}

function ruleUpdatedBadge() {
  return el("span", "RULE UPDATED", "badge badge-rule-updated");
}

function emptyFuture(title, reason) {
  const box = el("div", null, "empty-future");
  box.appendChild(el("span", title, "empty-future-title"));
  box.appendChild(el("p", reason));
  return box;
}

/* ------------------------------------------------------------ transport */

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail =
      body && body.detail
        ? typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail)
        : String(response.status);
    const err = new Error(detail);
    err.status = response.status;
    err.body = body;
    throw err;
  }
  return body;
}

function apiGet(path) {
  return api(path);
}

function apiPost(path, payload) {
  return api(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

/* -------------------------------------------------------------- storage */

function readLocal(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeLocal(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* a private window or blocked storage just means the choice is not remembered */
  }
}

/* ------------------------------------------------------------------ theme */

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "light") {
    root.setAttribute("data-theme", "light");
  } else {
    root.removeAttribute("data-theme");
  }
  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.textContent = mode === "light" ? "Dark theme" : "Light theme";
    toggle.setAttribute("aria-pressed", mode === "light" ? "true" : "false");
  }
}

function initTheme() {
  const stored = readLocal("flop-theme");
  const mode = stored === "light" ? "light" : "dark";
  applyTheme(mode);
  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(next);
      writeLocal("flop-theme", next);
    });
  }
}

/* -------------------------------------------------------------- routing */

const SCREENS = [
  "overview",
  "activity",
  "evidence",
  "technocore",
  "tclk",
  "inference",
  "passport",
  "safety",
  "sources",
  "settings",
];

function showScreen(name) {
  if (!SCREENS.includes(name)) {
    name = "overview";
  }
  for (const screen of SCREENS) {
    const section = document.getElementById("screen-" + screen);
    if (section) {
      section.hidden = screen !== name;
    }
  }
  document.querySelectorAll("[data-screen]").forEach((button) => {
    const on = button.getAttribute("data-screen") === name;
    if (on) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });
  const heading = document.querySelector("#screen-" + name + " h1");
  if (heading) {
    announce(heading.textContent + " screen");
  }
  if (name === "overview") loadOverview();
  if (name === "activity") loadActivity();
  if (name === "technocore") loadTechnocore();
  if (name === "tclk") loadTclk();
  if (name === "inference") loadInferenceState();
  if (name === "sources") loadSources();
  if (name === "settings") loadSettings();
}

function initNav() {
  document.querySelectorAll("[data-screen]").forEach((button) => {
    button.addEventListener("click", () => {
      const name = button.getAttribute("data-screen");
      navigateHash(name);
    });
  });
}

function navigateHash(screen, extra) {
  const suffix = extra ? "/" + extra : "";
  window.location.hash = "#/" + screen + suffix;
}

function currentRoute() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  if (hash) {
    const parts = hash.split("/").filter(Boolean);
    return { screen: parts[0], param: parts[1] };
  }
  const path = window.location.pathname;
  const match = path.match(/\/flop\/passport\/([^/]+)/);
  if (match) {
    return { screen: "passport", param: decodeURIComponent(match[1]) };
  }
  return { screen: "overview", param: undefined };
}

function onRouteChange() {
  const route = currentRoute();
  showScreen(route.screen);
  if (route.screen === "passport" && route.param) {
    const params = new URLSearchParams(window.location.search);
    const lineage = params.get("lineage") || subject.lineage;
    document.getElementById("passport-did").value = route.param;
    if (lineage) {
      document.getElementById("passport-lineage").value = lineage;
    }
    loadPassport(lineage, route.param);
  }
}

/* --------------------------------------------------------------- subject */

const subject = { lineage: "", did: "" };

function initSubject() {
  subject.lineage = readLocal("flop-lineage") || "";
  subject.did = readLocal("flop-did") || "";
  document.getElementById("subject-lineage").value = subject.lineage;
  document.getElementById("subject-did").value = subject.did;
  document.getElementById("passport-lineage").value = subject.lineage;
  document.getElementById("passport-did").value = subject.did;

  document.getElementById("subject-form").addEventListener("submit", (event) => {
    event.preventDefault();
    subject.lineage = document.getElementById("subject-lineage").value.trim();
    subject.did = document.getElementById("subject-did").value.trim();
    writeLocal("flop-lineage", subject.lineage);
    writeLocal("flop-did", subject.did);
    document.getElementById("passport-lineage").value = subject.lineage;
    document.getElementById("passport-did").value = subject.did;
    loadOverview();
    announce("Subject loaded");
  });
}

function subjectQuery() {
  return "lineage=" + encodeURIComponent(subject.lineage) + "&did=" + encodeURIComponent(subject.did);
}

function hasSubject() {
  return Boolean(subject.lineage && subject.did);
}

/* ------------------------------------------------------------- top strip */

let statusCache = null;

async function loadStatus() {
  const status = await apiGet("/v1/flop/status");
  statusCache = status;
  document.getElementById("phase-badge").textContent = status.networkPhaseBadge;
  document.getElementById("freshness").textContent = "Data as of " + status.dataFreshness;
  document.getElementById("security-status").textContent =
    status.walletCustody || status.holdsPrivateKeys
      ? "Security: custody in use"
      : "Security: no keys held, " + status.networkWritesPerformed + " network writes performed";
  document.getElementById("notice-affiliation").textContent = status.notices.affiliation;
  document.getElementById("notice-seed").textContent = status.notices.seedPhrase;
  // The synthetic banner belongs where it cannot be navigated away from. Activity
  // and Passport labelled their own records; Overview, which is the first screen
  // anybody sees, showed counts computed partly from mock data with no label at
  // all. This puts the label in the header for as long as the flag is on.
  const syntheticStrip = document.getElementById("notice-synthetic");
  syntheticStrip.hidden = !status.syntheticDataEnabled;
  syntheticStrip.textContent = status.syntheticDataEnabled
    ? (status.notices.synthetic || "SYNTHETIC MOCK DATA") +
      " - this console is showing synthetic records mixed with real ones."
    : "";
  document.getElementById("offline").hidden = true;
  return status;
}

function initSync() {
  document.getElementById("sync-btn").addEventListener("click", async () => {
    announce("Syncing (read-only)");
    await loadStatus();
    onRouteChange();
    announce("Sync complete");
  });
}

/* ------------------------------------------------------------- overview */

async function loadOverview() {
  const heroRow = document.getElementById("hero-row");
  const nextBest = document.getElementById("next-best-action");
  clear(heroRow);
  clear(nextBest);
  if (!hasSubject()) {
    heroRow.appendChild(note("Load a lineage id and a did:key above to see this subject's evidence."));
    return;
  }
  try {
    const [coverage, recommendations] = await Promise.all([
      apiGet("/v1/flop/coverage?" + subjectQuery()),
      apiGet("/v1/flop/recommendations?" + subjectQuery()),
    ]);

    const usefulWork = coverage.categories.find((entry) => entry.id === "useful-work");
    const inference = coverage.categories.find((entry) => entry.id === "inference");

    heroRow.appendChild(
      heroCard(
        "Useful work",
        usefulWork ? String(usefulWork.observed) : "0",
        usefulWork ? usefulWork.state : "NOT_OBSERVED",
        usefulWork ? usefulWork.reason : ""
      )
    );
    heroRow.appendChild(
      heroCard(
        "Inference",
        "Not yet available",
        inference ? inference.state : "NOT_YET_AVAILABLE",
        inference ? inference.reason : ""
      )
    );
    heroRow.appendChild(
      heroCard(
        coverage.label,
        coverage.covered + " / " + coverage.total + " categories",
        "coverage",
        "Not an airdrop score."
      )
    );
    if (coverage.containsSyntheticData || recommendations.containsSyntheticData) {
      const labelled = el("p", null, "hero-synthetic");
      labelled.appendChild(syntheticBadge());
      labelled.appendChild(
        el("span", " Some records counted above are synthetic and are not observations about this DID.")
      );
      heroRow.appendChild(labelled);
    }

    if (recommendations.nextBestAction) {
      const box = card(recommendations.nextBestAction.title);
      box.appendChild(note(recommendations.nextBestAction.reason));
      box.appendChild(
        pairs([
          ["Type", recommendations.nextBestAction.type],
          ["Official", recommendations.nextBestAction.official ? "yes" : "no"],
          ["Confidence", recommendations.nextBestAction.confidence],
        ])
      );
      nextBest.appendChild(box);
    } else {
      nextBest.appendChild(note("No suggestion available yet."));
    }
    if (coverage.categories.some((entry) => entry.state === "SOURCE_UNKNOWN")) {
      nextBest.appendChild(note("Some categories rest on sources this tool does not recognise."));
    }
  } catch (error) {
    problem(heroRow, "Could not load coverage: " + error.message);
  }
}

function heroCard(label, value, state, footnote) {
  const box = el("div", null, "hero-card");
  box.appendChild(el("span", label, "hero-label"));
  box.appendChild(el("span", value, "hero-value"));
  if (state) {
    box.appendChild(el("span", state, "badge badge-source-unknown"));
  }
  if (footnote) {
    box.appendChild(el("p", footnote, "hero-note"));
  }
  return box;
}

/* -------------------------------------------------------------- activity */

const ACTIVITY_FILTERS = [
  { id: "all", label: "All" },
  { id: "useful-work", label: "Useful Work" },
  { id: "technocore", label: "Technocore" },
  { id: "tclk", label: "tclk" },
  { id: "inference", label: "Inference" },
  { id: "creator", label: "Creator" },
  { id: "broker", label: "Broker" },
  { id: "security", label: "Security" },
];

const USEFUL_WORK_CATEGORIES = new Set([
  "code-contribution",
  "connector",
  "documentation",
  "translation",
  "bug-report",
  "reproducible-test",
  "security-finding",
  "useful-artifact",
  "protocol-implementation",
]);

function matchesFilter(record, filterId) {
  if (filterId === "all") return true;
  if (filterId === "useful-work") return !record.secondary && USEFUL_WORK_CATEGORIES.has(record.category);
  if (filterId === "technocore") return record.category === "room-participation" || record.category === "message-volume";
  if (filterId === "tclk") return record.category === "tclk-deal";
  if (filterId === "inference") return record.category === "inference";
  if (filterId === "security") return record.category === "security-finding";
  return false; // creator, broker: no category exists yet on this network phase
}

let activityRecords = [];
let activityFilter = "all";

function initActivityFilters() {
  const row = document.getElementById("activity-filters");
  clear(row);
  for (const filter of ACTIVITY_FILTERS) {
    const button = el("button", filter.label);
    button.type = "button";
    button.setAttribute("aria-pressed", filter.id === activityFilter ? "true" : "false");
    button.addEventListener("click", () => {
      activityFilter = filter.id;
      row.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", "false"));
      button.setAttribute("aria-pressed", "true");
      renderActivityList();
    });
    row.appendChild(button);
  }
}

async function loadActivity() {
  const list = document.getElementById("activity-list");
  clear(list);
  if (!hasSubject()) {
    list.appendChild(el("li", "Load a subject on the Overview screen first."));
    return;
  }
  try {
    const collection = await apiGet("/v1/flop/activities?" + subjectQuery());
    activityRecords = collection.records;
    renderActivityList();
  } catch (error) {
    problem(list, "Could not load activity: " + error.message);
  }
}

function renderActivityList() {
  const list = document.getElementById("activity-list");
  clear(list);
  if (activityFilter === "creator" || activityFilter === "broker") {
    const li = document.createElement("li");
    li.appendChild(
      emptyFuture(
        activityFilter === "creator" ? "Creator attribution" : "Broker demand contribution",
        "No official mechanism has been published for this on the current network phase."
      )
    );
    list.appendChild(li);
    return;
  }
  const shown = activityRecords.filter((record) => matchesFilter(record, activityFilter));
  if (shown.length === 0) {
    list.appendChild(el("li", "Nothing observed for this filter."));
    return;
  }
  for (const record of shown) {
    list.appendChild(activityCard(record));
  }
}

function activityCard(record) {
  const li = document.createElement("li");
  const box = el("div", null, "card");
  const row = el("div", null, "card-row");
  row.appendChild(el("strong", record.title));
  if (record.secondary) {
    row.appendChild(el("span", "SECONDARY (VOLUME)", "badge badge-source-unknown"));
  }
  if (record.synthetic) {
    row.appendChild(syntheticBadge());
  }
  box.appendChild(row);
  const badgeRow = el("div", null, "card-row");
  badgeRow.appendChild(sourceBadge(record.sourceClass));
  badgeRow.appendChild(evidenceBadge(record.evidenceLevel));
  badgeRow.appendChild(el("span", record.verificationState, "badge"));
  box.appendChild(badgeRow);
  box.appendChild(
    pairs([
      ["Category", record.category],
      ["Occurred", record.occurredAt],
      ["Source", record.sourceId],
    ])
  );
  const open = el("button", "Open in Evidence");
  open.type = "button";
  open.addEventListener("click", () => {
    navigateHash("evidence", record.id);
    showEvidenceRecord(record);
  });
  box.appendChild(open);
  li.appendChild(box);
  return li;
}

/* -------------------------------------------------------------- evidence */

function showEvidenceRecord(record) {
  const out = document.getElementById("evidence-detail");
  clear(out);
  const box = card(record.title);
  const badgeRow = el("div", null, "card-row");
  badgeRow.appendChild(sourceBadge(record.sourceClass));
  badgeRow.appendChild(evidenceBadge(record.evidenceLevel));
  if (record.synthetic) badgeRow.appendChild(syntheticBadge());
  box.appendChild(badgeRow);
  box.appendChild(
    pairs([
      ["Category", record.category],
      ["Occurred at", record.occurredAt],
      ["Source id", record.sourceId],
      ["Verification state", record.verificationState],
      ["Artifact hash", record.artifactHash],
      ["Artifact ref", record.artifactRef],
      ["Event id", record.eventId],
      ["Third-party ref", record.thirdPartyRef],
      ["Counterparties", record.counterparties.join(", ")],
      ["Secondary (volume only)", record.secondary ? "yes" : "no"],
    ])
  );
  if (record.detail) {
    box.appendChild(el("h3", "Detail"));
    box.appendChild(el("p", record.detail));
  }
  box.appendChild(rawJson(record));
  out.appendChild(box);
}

/* ------------------------------------------------------------ technocore */

async function loadTechnocore() {
  const out = document.getElementById("technocore-out");
  clear(out);
  if (!hasSubject()) {
    out.appendChild(note("Load a subject on the Overview screen first."));
    return;
  }
  try {
    const collection = await apiGet("/v1/flop/activities?" + subjectQuery());
    const records = collection.records.filter(
      (record) => record.category === "room-participation" || record.category === "message-volume"
    );
    out.appendChild(note("Volume is not evidence of useful participation."));
    if (records.length === 0) {
      out.appendChild(note("No Technocore participation observed for this subject."));
      return;
    }
    const list = el("ul", null, "rows");
    for (const record of records) {
      const li = document.createElement("li");
      li.appendChild(activityCardBody(record));
      list.appendChild(li);
    }
    out.appendChild(list);
  } catch (error) {
    problem(out, "Could not load Technocore activity: " + error.message);
  }
}

function activityCardBody(record) {
  const box = el("div", null, "card");
  const row = el("div", null, "card-row");
  row.appendChild(el("strong", record.title));
  if (record.secondary) row.appendChild(el("span", "SECONDARY (VOLUME)", "badge badge-source-unknown"));
  box.appendChild(row);
  box.appendChild(pairs([["Occurred", record.occurredAt], ["Source", record.sourceId]]));
  return box;
}

/* ------------------------------------------------------------------ tclk */

async function loadTclk() {
  const out = document.getElementById("tclk-out");
  clear(out);
  if (!hasSubject()) {
    out.appendChild(note("Load a subject on the Overview screen first."));
    return;
  }
  try {
    const collection = await apiGet("/v1/flop/activities?" + subjectQuery());
    const records = collection.records.filter((record) => record.category === "tclk-deal");
    if (records.length === 0) {
      out.appendChild(note("No tclk/1 deal activity observed for this subject."));
      return;
    }
    const list = el("ul", null, "rows");
    for (const record of records) {
      const li = document.createElement("li");
      li.appendChild(activityCardBody(record));
      list.appendChild(li);
    }
    out.appendChild(list);
  } catch (error) {
    problem(out, "Could not load tclk activity: " + error.message);
  }
}

/* -------------------------------------------------------------- inference */

let lastPrepared = null;

function markWizardStep(step) {
  const order = ["purpose", "quote", "review", "run"];
  const index = order.indexOf(step);
  document.querySelectorAll("#wizard-steps li").forEach((item) => {
    const itemIndex = order.indexOf(item.getAttribute("data-step"));
    item.removeAttribute("aria-current");
    item.removeAttribute("data-done");
    if (itemIndex < index) item.setAttribute("data-done", "true");
    if (itemIndex === index) item.setAttribute("aria-current", "step");
  });
}

async function loadInferenceState() {
  const out = document.getElementById("inference-state");
  const liveOut = document.getElementById("inference-live-out");
  clear(out);
  clear(liveOut);
  markWizardStep("purpose");
  try {
    const [status, state] = await Promise.all([
      apiGet("/v1/flop/status"),
      apiGet("/v1/flop/testnet/state"),
    ]);
    out.appendChild(
      emptyFuture(
        "Waiting for official FLOP Testnet",
        status.officialTestnetReason
      )
    );
    out.appendChild(
      pairs([
        ["Network phase", state.networkPhaseBadge],
        ["Kill switch", state.killSwitch.display],
        ["Executable endpoints", state.endpoints.executableCount],
        ["Simulation origin", state.endpoints.simulationOrigin],
        ["Signer", state.signer.custody + ", " + state.signer.reason],
      ])
    );

    const faucetBtn = el("button", "Faucet (real testnet)");
    faucetBtn.type = "button";
    faucetBtn.disabled = true;
    const runBtn = el("button", "Execute (real testnet)");
    runBtn.type = "button";
    runBtn.disabled = true;
    liveOut.appendChild(el("p", "Faucet: " + state.faucet + " -- no official faucet is published."));
    liveOut.appendChild(faucetBtn);
    liveOut.appendChild(el("p", "Execute: " + state.faucet + " -- refused before any network is reached."));
    liveOut.appendChild(runBtn);
    liveOut.appendChild(note("Only the simulation below runs; it reaches an origin that RFC 6761 guarantees cannot resolve."));
  } catch (error) {
    problem(out, "Could not load testnet state: " + error.message);
  }
}

function initInferenceForm() {
  document.getElementById("inference-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const out = document.getElementById("inference-out");
    clear(out);
    if (!hasSubject()) {
      out.appendChild(note("Load a subject on the Overview screen first."));
      return;
    }
    const body = {
      lineage: subject.lineage,
      did: subject.did,
      prompt: document.getElementById("inference-prompt").value,
      purpose: document.getElementById("inference-purpose").value,
      maxSpend: document.getElementById("inference-max-spend").value || "5",
      evidenceLabel: document.getElementById("inference-evidence-label").value || null,
    };
    try {
      markWizardStep("quote");
      const quote = await apiPost("/v1/flop/testnet/inference/quote", {
        lineage: body.lineage,
        did: body.did,
      });
      const quoteBox = card("Quote");
      quoteBox.appendChild(el("span", quote.banner, "badge badge-safety-caution"));
      quoteBox.appendChild(
        pairs([
          ["Amount", quote.quote.amount + " " + quote.quote.currency],
          ["Official pricing available", quote.officialPricingAvailable ? "yes" : "no"],
          ["Reason", quote.reason],
        ])
      );
      out.appendChild(quoteBox);

      markWizardStep("review");
      const prepared = await apiPost("/v1/flop/testnet/inference/prepare", body);
      lastPrepared = prepared;
      const reviewBox = card("Security review");
      reviewBox.appendChild(safetyBadge(prepared.safetyLevel, prepared.safetyLevel));
      reviewBox.appendChild(
        pairs([
          ["Canonical destination", prepared.canonicalDestination],
          ["Request hash", prepared.requestHash],
          ["Estimated spend", prepared.estimatedTestFlopSpend],
          ["Max allowed spend", prepared.maxAllowedSpend],
          ["Expires at", prepared.expiresAt],
        ])
      );
      if (prepared.safetyFindings && prepared.safetyFindings.length > 0) {
        const list = el("ul", null, "rows");
        for (const finding of prepared.safetyFindings) {
          const li = document.createElement("li");
          li.appendChild(safetyBadge(finding.level, finding.display));
          li.appendChild(el("p", finding.reason));
          list.appendChild(li);
        }
        reviewBox.appendChild(list);
      }
      out.appendChild(reviewBox);
      document.getElementById("inference-run-btn").disabled = false;
      markWizardStep("run");
    } catch (error) {
      problem(out, "Prepare refused: " + error.message);
    }
  });

  document.getElementById("inference-run-btn").addEventListener("click", async () => {
    const out = document.getElementById("inference-out");
    if (!hasSubject()) return;
    const body = {
      lineage: subject.lineage,
      did: subject.did,
      prompt: document.getElementById("inference-prompt").value,
      purpose: document.getElementById("inference-purpose").value,
      maxSpend: document.getElementById("inference-max-spend").value || "5",
      evidenceLabel: document.getElementById("inference-evidence-label").value || null,
    };
    const pasted = document.getElementById("inference-receipt").value.trim();
    if (pasted) {
      try {
        body.approvalReceipt = JSON.parse(pasted);
      } catch (error) {
        problem(out, "The approval receipt is not valid JSON: " + error.message);
        return;
      }
    }
    try {
      const run = await apiPost("/v1/flop/testnet/simulation/run", body);
      const runBox = card("Approve & Run (SIMULATION)");
      runBox.appendChild(el("span", run.banner, "badge badge-safety-caution"));
      runBox.appendChild(el("span", run.syntheticBanner, "badge badge-synthetic"));
      runBox.appendChild(
        pairs([
          ["Outcome ok", run.ok ? "yes" : "no"],
          ["Transport calls", run.transportCalls],
          ["Network writes performed", run.networkWritesPerformed],
          ["Approval receipt", run.approvalReceipt ? run.approvalReceipt.source : "--"],
          ["Approver", run.approvalReceipt ? run.approvalReceipt.approver : "--"],
        ])
      );
      if (run.approvalReceipt) {
        runBox.appendChild(el("p", run.approvalReceipt.note, "hint"));
      }
      const steps = el("ul", null, "rows");
      for (const step of run.steps) {
        const li = document.createElement("li");
        li.appendChild(el("strong", step.label + (step.ok ? " -- ok" : " -- refused")));
        li.appendChild(el("p", step.detail));
        steps.appendChild(li);
      }
      runBox.appendChild(steps);
      runBox.appendChild(rawJson(run));
      out.appendChild(runBox);
      markWizardStep("run");
      document.querySelector('#wizard-steps li[data-step="run"]').setAttribute("data-done", "true");
    } catch (error) {
      problem(out, "Simulation refused: " + error.message);
    }
  });
}

/* -------------------------------------------------------------- passport */

async function loadPassport(lineage, did) {
  const out = document.getElementById("passport-out");
  clear(out);
  if (!lineage || !did) {
    out.appendChild(note("A lineage id and a did:key are both required."));
    return;
  }
  try {
    const passport = await apiGet(
      "/v1/flop/passport/" + encodeURIComponent(did) + "?lineage=" + encodeURIComponent(lineage)
    );
    if (passport.banner) {
      out.appendChild(syntheticBadge());
    }
    const summaryBox = card("Summary");
    summaryBox.appendChild(el("span", passport.networkPhaseBadge, "badge badge-phase"));
    summaryBox.appendChild(
      pairs([
        ["Generated at", passport.generatedAt],
        ["Useful work records", passport.summary.usefulWork],
        ["Total activity records", passport.summary.activityRecords],
        ["Safety findings", passport.summary.safetyFindings],
        ["Wash signals", passport.summary.washSignals],
        [passport.evidenceCoverage.label, passport.evidenceCoverage.covered + " / " + passport.evidenceCoverage.total],
      ])
    );
    summaryBox.appendChild(note(passport.summary.volumeNote));
    out.appendChild(summaryBox);

    const coverageBox = card("Coverage categories");
    const list = el("ul", null, "rows");
    for (const category of passport.evidenceCoverage.categories) {
      const li = document.createElement("li");
      li.appendChild(el("strong", category.label));
      li.appendChild(el("span", " " + category.state, "badge"));
      li.appendChild(el("p", category.reason));
      list.appendChild(li);
    }
    coverageBox.appendChild(list);
    out.appendChild(coverageBox);

    if (passport.warnings.length > 0) {
      const warnBox = card("Warnings");
      for (const warning of passport.warnings) {
        warnBox.appendChild(el("p", warning, "note"));
      }
      out.appendChild(warnBox);
    }

    out.appendChild(rawJson(passport));
  } catch (error) {
    problem(out, "Could not load passport: " + error.message);
  }
}

function initPassportForm() {
  document.getElementById("passport-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const lineage = document.getElementById("passport-lineage").value.trim();
    const did = document.getElementById("passport-did").value.trim();
    navigateHash("passport", did + (lineage ? "?lineage=" + encodeURIComponent(lineage) : ""));
    loadPassport(lineage, did);
  });
}

/* ---------------------------------------------------------------- safety */

function initSafetyForm() {
  document.getElementById("safety-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const out = document.getElementById("safety-out");
    clear(out);
    const text = document.getElementById("safety-text").value;
    const sourceClass = document.getElementById("safety-source-class").value || null;
    try {
      const report = await apiPost("/v1/flop/safety/scan", {
        text,
        sourceClass,
      });
      const box = card("Scan result");
      box.appendChild(safetyBadge(report.level, report.display));
      box.appendChild(note(report.note));
      if (report.findings.length === 0) {
        box.appendChild(note("Nothing matched. A clean scan is not permission to act on this text."));
      } else {
        const list = el("ul", null, "rows");
        for (const finding of report.findings) {
          const li = document.createElement("li");
          li.appendChild(safetyBadge(finding.level, finding.display));
          li.appendChild(el("p", finding.reason));
          if (finding.excerpt) {
            li.appendChild(el("pre", finding.excerpt));
          }
          list.appendChild(li);
        }
        box.appendChild(list);
      }
      out.appendChild(box);
    } catch (error) {
      problem(out, "Scan failed: " + error.message);
    }
  });
}

/* --------------------------------------------------------------- sources */

async function loadSources() {
  const sourcesOut = document.getElementById("sources-out");
  const rulesOut = document.getElementById("rules-out");
  clear(sourcesOut);
  clear(rulesOut);
  try {
    const [sources, rules] = await Promise.all([
      apiGet("/v1/flop/sources"),
      apiGet("/v1/flop/rules"),
    ]);
    const table = document.createElement("table");
    table.className = "data-table";
    const head = document.createElement("tr");
    for (const label of ["Source", "URL", "Status", "Version", "Fetched", "Hash"]) {
      head.appendChild(el("th", label));
    }
    table.appendChild(head);
    for (const snapshot of sources.sources || []) {
      const row = document.createElement("tr");
      row.appendChild(el("td", snapshot.id));
      row.appendChild(el("td", snapshot.url));
      row.appendChild(el("td", snapshot.status));
      row.appendChild(el("td", snapshot.versionHint));
      row.appendChild(el("td", snapshot.fetchedAt));
      row.appendChild(el("td", snapshot.sha256));
      table.appendChild(row);
    }
    sourcesOut.appendChild(table);

    if (rules.rules.length === 0) {
      rulesOut.appendChild(note("No rules registered."));
    }
    for (const rule of rules.rules) {
      const box = card(rule.id);
      const row = el("div", null, "card-row");
      row.appendChild(el("span", rule.status, "badge"));
      if (rule.freshness && rule.freshness.label) {
        row.appendChild(ruleUpdatedBadge());
      }
      box.appendChild(row);
      box.appendChild(el("p", rule.statement));
      box.appendChild(
        pairs([
          ["Source id", rule.source.sourceId],
          ["Source URL", rule.source.sourceUrl],
          ["Source version", rule.source.sourceVersion],
          ["Source date", rule.source.sourceDate],
          ["Fetched at", rule.source.fetchedAt],
          ["Derivation", rule.derivation],
        ])
      );
      rulesOut.appendChild(box);
    }
  } catch (error) {
    problem(sourcesOut, "Could not load sources: " + error.message);
  }
}

/* -------------------------------------------------------------- settings */

async function loadSettings() {
  const out = document.getElementById("settings-out");
  clear(out);
  try {
    const [status, state] = await Promise.all([
      apiGet("/v1/flop/status"),
      apiGet("/v1/flop/testnet/state"),
    ]);
    const box = card("Kill switch");
    box.appendChild(el("p", state.killSwitch.display));
    box.appendChild(
      pairs([
        ["Engaged", state.killSwitch.engaged ? "yes" : "no"],
        ["Locked", state.killSwitch.locked ? "yes" : "no"],
        ["Network writes allowed", state.networkWritesAllowed ? "yes" : "no"],
      ])
    );
    out.appendChild(box);

    const spendBox = card("Spend policy");
    spendBox.appendChild(
      pairs([
        ["Per-action max", state.spendPolicy.perActionMax + " " + state.spendPolicy.unit],
        ["Daily max", state.spendPolicy.dailyMax + " " + state.spendPolicy.unit],
        ["Session max", state.spendPolicy.sessionMax + " " + state.spendPolicy.unit],
        ["Approval required above", state.spendPolicy.approvalRequiredAbove + " " + state.spendPolicy.unit],
      ])
    );
    spendBox.appendChild(note(state.spendPolicy.notice));
    out.appendChild(spendBox);

    const custodyBox = card("Custody and writes");
    custodyBox.appendChild(
      pairs([
        ["Holds private keys", status.holdsPrivateKeys ? "yes" : "no"],
        ["Wallet custody", status.walletCustody ? "yes" : "no"],
        ["Network writes performed", status.networkWritesPerformed],
        ["Signer", state.signer.custody + " -- " + state.signer.reason],
      ])
    );
    out.appendChild(custodyBox);

    const mainnetBox = card("Mainnet");
    mainnetBox.appendChild(el("p", state.mainnet.rule.statement));
    mainnetBox.appendChild(note(state.mainnet.note));
    out.appendChild(mainnetBox);

    const resetBtn = el("button", "Reset local preferences (theme, subject)");
    resetBtn.type = "button";
    resetBtn.addEventListener("click", () => {
      try {
        window.localStorage.removeItem("flop-theme");
        window.localStorage.removeItem("flop-lineage");
        window.localStorage.removeItem("flop-did");
      } catch {
        /* nothing was stored to begin with */
      }
      applyTheme("dark");
      announce("Local preferences cleared");
    });
    out.appendChild(resetBtn);
  } catch (error) {
    problem(out, "Could not load settings: " + error.message);
  }
}

/* -------------------------------------------------------------------- init */

async function main() {
  initTheme();
  initNav();
  initSubject();
  initSync();
  initActivityFilters();
  initInferenceForm();
  initPassportForm();
  initSafetyForm();
  window.addEventListener("hashchange", onRouteChange);

  try {
    await loadStatus();
  } catch {
    document.getElementById("offline").hidden = false;
  }
  onRouteChange();
}

main();
