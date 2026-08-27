"use strict";

/* The Explorer.
 *
 * Two rules run through every line of this file.
 *
 * 1. No string ever becomes markup. Every value shown here -- room names, task
 *    titles, dispute statements, profile text, fleet names -- was written by
 *    somebody else. The builders refuse control characters, but that is a
 *    different defence at a different layer and it is not this one. A viewer
 *    that executed what it displayed would be a worse problem than anything it
 *    was built to show, so text reaches the page through textContent and
 *    through nothing else. A test reads this file and fails on every construct
 *    that could turn a string into markup, which is why none of them are
 *    spelled out even in a comment.
 *
 * 2. This page verifies nothing. It renders what a local API already checked.
 *    Every screen says so, because a viewer that looks like a verifier gets
 *    believed like one.
 */

const NO_KEYS_HERE =
  "This page holds no keys, signs nothing and sends nothing. It reads.";

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

function pairs(entries) {
  const list = document.createElement("dl");
  for (const [key, value] of entries) {
    list.appendChild(el("dt", key));
    list.appendChild(el("dd", value === null || value === undefined ? "--" : value));
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

/* `docs/17` fixes the status vocabulary and forbids three phrases outright. A
 * status here only ever repeats a value the API already produced, and a test
 * checks the forbidden phrases appear nowhere in these files. */
function status(text, tone) {
  return el("span", text, "status " + (tone || "caution"));
}

function note(text) {
  return el("p", text, "note");
}

function problem(where, message) {
  clear(where);
  where.appendChild(el("p", message, "warn"));
}

function listOf(values) {
  const list = el("ul", null, "rows");
  for (const value of values) {
    list.appendChild(el("li", value));
  }
  return list;
}

function json(value) {
  return el("pre", JSON.stringify(value, null, 2));
}

/* ------------------------------------------------------------ transport */

let currentLineage = null;

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : response.status;
    throw new Error(String(detail));
  }
  return body;
}

function needLineage(where) {
  if (currentLineage) {
    return true;
  }
  problem(where, "Pick a lineage on the Lineages screen first.");
  return false;
}

/* ------------------------------------------------------------ screens */

const screens = document.querySelectorAll(".screen");
const tabs = document.querySelectorAll("nav button");

for (const tab of tabs) {
  tab.addEventListener("click", () => {
    for (const other of tabs) {
      other.classList.toggle("on", other === tab);
    }
    for (const screen of screens) {
      screen.hidden = screen.id !== "screen-" + tab.dataset.screen;
    }
    if (tab.dataset.screen === "graph") {
      void showGraph();
    }
    if (tab.dataset.screen === "exchange") {
      void showExchange();
    }
    if (tab.dataset.screen === "inspector") {
      void showMeta();
    }
  });
}

/* -- lineages ------------------------------------------------------------ */

async function loadLineages() {
  const list = document.getElementById("lineage-list");
  const detail = document.getElementById("lineage-detail");
  try {
    const body = await api("/v1/lineages");
    clear(list);
    const ids = body.lineages || [];
    if (ids.length === 0) {
      list.appendChild(el("li", "This index holds no lineages yet."));
      return;
    }
    for (const id of ids) {
      const row = document.createElement("li");
      const button = el("button", id);
      button.type = "button";
      button.addEventListener("click", () => {
        currentLineage = id;
        void showLineage(id, detail);
      });
      row.appendChild(button);
      list.appendChild(row);
    }
    currentLineage = ids[0];
    await showLineage(ids[0], detail);
  } catch (error) {
    document.getElementById("offline").hidden = false;
    problem(list, "Could not reach the local API: " + error.message);
  }
}

async function showLineage(id, where) {
  clear(where);
  const body = await api("/v1/lineages/" + encodeURIComponent(id));
  const box = card("Lineage");
  const resolved = body.resolved === true;
  box.appendChild(
    status(resolved ? "valid authority chain" : String(body.reason || "unresolved"),
      resolved ? "allow" : "deny")
  );
  box.appendChild(
    pairs([
      ["lineage", body.lineage],
      ["root", body.root],
      ["epoch", body.epoch],
      ["detail", body.detail],
    ])
  );
  if (Array.isArray(body.superseded) && body.superseded.length) {
    box.appendChild(el("h3", "superseded roots"));
    box.appendChild(listOf(body.superseded));
    box.appendChild(
      note(
        "Superseded means this protocol no longer treats that key as the " +
          "lineage's current root. It does not mean the key's signatures stop " +
          "verifying -- did:key has no revocation, and a superseded key keeps " +
          "producing mathematically valid signatures forever."
      )
    );
  }
  for (const warning of body.warnings || []) {
    box.appendChild(el("p", warning, "warn"));
  }
  if (body.note) {
    box.appendChild(note(body.note));
  }
  where.appendChild(box);
}

/* -- authority graph ----------------------------------------------------- */

async function showGraph() {
  const where = document.getElementById("graph-out");
  if (!needLineage(where)) {
    return;
  }
  try {
    const body = await api("/v1/lineages/" + encodeURIComponent(currentLineage) + "/graph");
    clear(where);
    const nodes = card("Nodes");
    for (const node of body.nodes || []) {
      nodes.appendChild(pairs([[(node.kinds || ["node"]).join(", "), node.did]]));
    }
    where.appendChild(nodes);

    const edges = card("Edges");
    for (const edge of body.edges || []) {
      const row = el("div", null, "card");
      row.appendChild(status(String(edge.kind), edge.live ? "allow" : "deny"));
      row.appendChild(
        pairs([
          ["from", edge.source],
          ["to", edge.target],
          ["scope", edge.label],
          ["live", String(edge.live)],
          ["reason", edge.reason],
          ["detail", edge.detail],
          ["event", edge.eventId],
        ])
      );
      edges.appendChild(row);
    }
    where.appendChild(edges);
    for (const warning of body.warnings || []) {
      where.appendChild(el("p", warning, "warn"));
    }
    if (body.note) {
      where.appendChild(note(body.note));
    }
  } catch (error) {
    problem(where, error.message);
  }
}

/* -- did ----------------------------------------------------------------- */

document.getElementById("did-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const where = document.getElementById("did-out");
  const did = document.getElementById("did-input").value.trim();
  try {
    const body = await api("/v1/dids/" + encodeURIComponent(did));
    clear(where);
    const box = card("DID");
    box.appendChild(
      pairs([
        ["did", body.did],
        ["method", body.method],
        ["key type", body.keyType],
      ])
    );
    box.appendChild(note(body.note || NO_KEYS_HERE));
    where.appendChild(box);
  } catch (error) {
    problem(where, error.message);
  }
});

/* -- passport ------------------------------------------------------------ */

document.getElementById("passport-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const where = document.getElementById("passport-out");
  if (!needLineage(where)) {
    return;
  }
  const did = document.getElementById("passport-did").value.trim();
  try {
    const body = await api(
      "/v1/passports/" + encodeURIComponent(did) + "?lineage=" + encodeURIComponent(currentLineage)
    );
    clear(where);

    const sections = [
      ["Self-claimed", body.selfClaimed],
      ["Cryptographically linked", body.cryptographicallyLinked],
      ["Evidence-supported", body.evidenceSupported],
      ["Third-party attested", body.thirdPartyAttested],
    ];
    for (const [title, section] of sections) {
      const box = card(title);
      box.appendChild(json(section));
      where.appendChild(box);
    }

    if (body.disputes) {
      const box = card("Disputes");
      const cases = body.disputes.cases || [];
      if (cases.length === 0) {
        box.appendChild(el("p", "No case in this bundle names this DID."));
      }
      for (const entry of cases) {
        box.appendChild(
          pairs([
            ["case", entry.case],
            ["roles", (entry.roles || []).join(", ")],
            ["outcome", entry.outcome],
            ["needed conflicted votes", String(entry.dependsOnConflictedJurors)],
          ])
        );
      }
      box.appendChild(note(body.disputes.note));
      where.appendChild(box);
    }

    const missing = body.notIncluded || [];
    const absent = card("Not included");
    if (missing.length === 0) {
      absent.appendChild(
        el("p", "Nothing. Every section the specification asks for has a phase behind it.")
      );
    } else {
      for (const item of missing) {
        absent.appendChild(pairs([[item.section, item.reason]]));
      }
    }
    absent.appendChild(
      note(
        "This section exists so an empty list above reads as 'none found' " +
          "rather than 'not tracked'. They are different facts."
      )
    );
    where.appendChild(absent);

    for (const warning of body.warnings || []) {
      where.appendChild(el("p", warning, "warn"));
    }
    where.appendChild(note(body.note));
  } catch (error) {
    problem(where, error.message);
  }
});

/* -- router -------------------------------------------------------------- */

document.getElementById("router-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const where = document.getElementById("router-out");
  if (!needLineage(where)) {
    return;
  }
  const raw = document.getElementById("router-skills").value;
  const skills = raw
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  try {
    const body = await api("/v1/router/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lineage: currentLineage, skills: skills }),
    });
    clear(where);

    const weights = card("Published weights");
    weights.appendChild(
      pairs([
        ["ranking version", body.rankingVersion],
        ["candidates considered", body.considered],
      ])
    );
    weights.appendChild(json(body.weights));
    where.appendChild(weights);

    const found = body.candidates || [];
    if (found.length === 0) {
      where.appendChild(el("p", "No candidate in this bundle matched."));
    }
    for (const candidate of found) {
      const box = card(candidate.did);
      box.appendChild(
        pairs([
          ["relevance", candidate.relevance],
          ["authority satisfied", String(candidate.authoritySatisfied)],
          ["matched skills", (candidate.matchedSkills || []).join(", ") || "none"],
          ["evidence-supported", (candidate.evidenceSupportedSkills || []).join(", ") || "none"],
        ])
      );

      box.appendChild(el("h3", "contributions"));
      let total = 0;
      for (const contribution of candidate.contributions || []) {
        total += Number(contribution.value) || 0;
        box.appendChild(
          pairs([
            [
              contribution.name,
              String(contribution.count) +
                " x " +
                String(contribution.weight) +
                " = " +
                String(contribution.value),
            ],
            ["", contribution.detail],
          ])
        );
      }
      box.appendChild(
        note(
          "These sum to " +
            String(total) +
            ", which is the relevance above. That is the point of publishing them: " +
            "the ranking can be recomputed rather than believed."
        )
      );

      if (candidate.relationshipShape) {
        box.appendChild(el("h3", "relationship shape"));
        box.appendChild(json(candidate.relationshipShape));
      }
      where.appendChild(box);
    }
    where.appendChild(note(body.note));
  } catch (error) {
    problem(where, error.message);
  }
});

/* -- exchange ------------------------------------------------------------ */

async function showExchange() {
  const where = document.getElementById("exchange-out");
  if (!needLineage(where)) {
    return;
  }
  try {
    const body = await api("/v1/exchange?lineage=" + encodeURIComponent(currentLineage));
    clear(where);
    const listings = body.listings || [];
    if (listings.length === 0) {
      where.appendChild(el("p", "No task in this bundle."));
    }
    for (const listing of listings) {
      const box = card(listing.title);
      box.appendChild(status(String(listing.status), toneFor(listing.status)));
      box.appendChild(
        pairs([
          ["task", listing.task],
          ["requester", listing.requester],
          ["task status", listing.taskStatus],
          ["detail", listing.detail],
          ["open slots", listing.openSlots],
          ["cancellable", String(listing.cancellable)],
          ["reward reference", listing.rewardReference],
        ])
      );
      if (listing.claimContest) {
        const contest = card("Competing claims");
        for (const claim of listing.claimContest.competing || []) {
          contest.appendChild(pairs([[claim.claimant, claim.claim]]));
        }
        contest.appendChild(
          pairs([["awarded", listing.claimContest.awardedClaim || "nobody"]])
        );
        contest.appendChild(note(listing.claimContest.note));
        box.appendChild(contest);
      }
      for (const warning of listing.warnings || []) {
        box.appendChild(el("p", warning, "warn"));
      }
      where.appendChild(box);
    }
    if (body.hiddenCount) {
      where.appendChild(
        el("p", String(body.hiddenCount) + " listing(s) hidden by a filter.", "warn")
      );
    }
    where.appendChild(note(body.note));
  } catch (error) {
    problem(where, error.message);
  }
}

function toneFor(value) {
  if (value === "VERIFIED_ACCEPTED") {
    return "allow";
  }
  if (value === "VERIFIED_REJECTED" || value === "CANCELLED") {
    return "deny";
  }
  return "caution";
}

/* -- dispute ------------------------------------------------------------- */

document.getElementById("dispute-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const where = document.getElementById("dispute-out");
  if (!needLineage(where)) {
    return;
  }
  const caseId = document.getElementById("dispute-case").value.trim();
  try {
    const body = await api(
      "/v1/disputes/" + encodeURIComponent(caseId) + "?lineage=" + encodeURIComponent(currentLineage)
    );
    clear(where);
    const box = card("Outcome");
    box.appendChild(status(String(body.outcome), body.outcome === "UNDECIDED" ? "caution" : "allow"));
    box.appendChild(
      pairs([
        ["detail", body.detail],
        ["task", body.task],
        ["opener", body.opener],
        ["statement", body.statement],
        ["seats", body.policy ? body.policy.seats : null],
        ["quorum", body.policy ? body.policy.quorum : null],
        ["threshold", body.policy ? body.policy.threshold : null],
      ])
    );
    where.appendChild(box);

    const tally = card("Tally");
    tally.appendChild(json(body.tally));
    where.appendChild(tally);

    const jurors = card("Jurors");
    for (const juror of body.jurors || []) {
      jurors.appendChild(
        pairs([
          [juror.juror, String(juror.finding || "has not voted")],
          ["disclosed", (juror.disclosedConflicts || []).join(", ") || "none"],
          ["detected", (juror.detectedConflicts || []).join(", ") || "none"],
          ["undisclosed", (juror.undisclosedConflicts || []).join(", ") || "none"],
        ])
      );
    }
    where.appendChild(jurors);

    const without = card("Without the conflicted jurors");
    without.appendChild(
      pairs([
        ["outcome", body.outcomeWithoutConflictedJurors],
        ["outcome depended on them", String(body.outcomeDependsOnConflictedJurors)],
      ])
    );
    where.appendChild(without);

    for (const warning of body.warnings || []) {
      where.appendChild(el("p", warning, "warn"));
    }
    where.appendChild(note(body.note));
  } catch (error) {
    problem(where, error.message);
  }
});

/* -- inspector ----------------------------------------------------------- */

document.getElementById("event-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const where = document.getElementById("event-out");
  const id = document.getElementById("event-id").value.trim();
  try {
    const body = await api("/v1/events/" + encodeURIComponent(id));
    clear(where);
    const box = card("Envelope");
    box.appendChild(json(body));
    box.appendChild(
      note(
        "The raw event, so the id can be recomputed and the signatures checked " +
          "somewhere that actually checks them. This page does not."
      )
    );
    where.appendChild(box);
  } catch (error) {
    problem(where, error.message);
  }
});

async function showMeta() {
  const where = document.getElementById("meta-out");
  try {
    const body = await api("/v1/meta");
    clear(where);
    const box = card(null);
    box.appendChild(
      pairs([
        ["version", body.version],
        ["protocol", body.protocol],
        ["holds private keys", String(body.holdsPrivateKeys)],
        ["accepts events over HTTP", String(body.acceptsEventsOverHttp)],
      ])
    );
    box.appendChild(note(body.note));
    where.appendChild(box);
  } catch (error) {
    problem(where, error.message);
  }
}

void loadLineages();
