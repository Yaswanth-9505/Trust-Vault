/* TrustVault front end.
 *
 * Nothing in here is a security control. The server decides every access;
 * this file only hides buttons that would be refused anyway. User-supplied
 * text is only ever put into the page with textContent (via h()), never
 * innerHTML, so a document titled <script> is just a strange title.
 */
"use strict";

const state = { user: null, csrf: null, categories: ["HR", "Legal", "Finance", "Engineering", "Audit", "General"] };

// ---------------------------------------------------------------- helpers
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function toast(msg, bad) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " bad" : "");
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
}

function fmtDate(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
function levelMark(level) {
  const names = { owner: "Owner", edit: "Can edit", read: "Can read" };
  return h("span", { class: "level " + level }, names[level] || level);
}

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body, isForm) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET" && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
  if (body !== undefined) {
    if (isForm) opts.body = body;
    else { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (res.status === 401 && path !== "/api/auth/login") {
    state.user = null;
    location.hash = "#/login";
    throw new ApiError(401, "Your session has ended. Please sign in again.");
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.message) || "Request failed.");
  return data;
}

function errorBox(err) { return h("p", { class: "error", role: "alert" }, err.message || String(err)); }

// ---------------------------------------------------------------- shell
function shell(active, ...content) {
  const icons = {
    documents: "📄",
    upload: "📤",
    trash: "🗑️",
    admin: "🛡️",
    account: "⚙️"
  };
  const link = (href, label, key) =>
    h("a", { href, "aria-current": active === key ? "page" : null, class: "nav-item" },
      h("span", { class: "nav-icon" }, icons[key] || "•"),
      h("span", { class: "nav-label" }, label));
  const u = state.user;
  const initials = (u.name || "U").split(" ").map((w) => w[0]).join("").slice(0, 2).toUpperCase();
  return h("div", { class: "shell" },
    h("nav", { class: "side", "aria-label": "Main" },
      h("div", { class: "brand" },
        h("div", { class: "brand-logo" }, "🔐"),
        h("div", { class: "brand-text" },
          h("div", { class: "brand-title" }, "TrustVault"),
          h("small", { class: "brand-badge" }, "CONFIDENTIAL"))),
      h("div", { class: "nav-links" },
        link("#/documents", "Documents", "documents"),
        u.role === "owner" ? link("#/upload", "Upload", "upload") : null,
        u.role !== "admin" ? link("#/trash", "Trash", "trash") : null,
        u.role === "admin" ? link("#/admin", "Administration", "admin") : null,
        link("#/account", "Account", "account")),
      h("div", { class: "who" },
        h("div", { class: "who-user-card" },
          h("div", { class: "who-avatar" }, initials),
          h("div", { class: "who-details" },
            h("strong", { class: "who-name" }, u.name),
            h("span", { class: "who-email" }, u.email),
            h("span", { class: "role-pill role-" + u.role }, u.role.toUpperCase()))),
        h("button", { class: "btn-signout", onclick: logout, title: "Sign out" }, "Sign out ⎋"))),
    h("main", { class: "main" }, ...content));
}

async function logout() {
  try { await api("POST", "/api/auth/logout"); } catch (_) { /* ignore */ }
  state.user = null; state.csrf = null;
  location.hash = "#/login";
}

function render(node) {
  const app = document.getElementById("app");
  app.replaceChildren(node);
  const heading = app.querySelector("h1");
  if (heading) { heading.setAttribute("tabindex", "-1"); heading.focus({ preventScroll: true }); }
}

// ---------------------------------------------------------------- login
function viewLogin() {
  const err = h("div");
  const email = h("input", { id: "email", type: "email", autocomplete: "username", placeholder: "e.g. olivia@trustvault.test", required: true });
  const pw = h("input", { id: "pw", type: "password", autocomplete: "current-password", placeholder: "••••••••••••", required: true });

  const demoAccounts = [
    { label: "Olivia (Owner)", email: "olivia@trustvault.test", pass: "Olivia-Demo-2026!", desc: "Owns documents" },
    { label: "Asha (Admin)", email: "admin@trustvault.test", pass: "Admin-Demo-2026!", desc: "Audit & users" },
    { label: "Vera (Viewer)", email: "vera@trustvault.test", pass: "Vera-Demo-2026!", desc: "Read & edit" },
    { label: "Victor (Viewer)", email: "victor@trustvault.test", pass: "Victor-Demo-2026!", desc: "Viewer" },
    { label: "Oscar (Owner)", email: "oscar@trustvault.test", pass: "Oscar-Demo-2026!", desc: "Private files" },
    { label: "Pat (Partner)", email: "ext@partner.test", pass: "Partner-Demo-2026!", desc: "External" },
  ];

  const fill = (acc) => {
    email.value = acc.email;
    pw.value = acc.pass;
    err.replaceChildren();
  };

  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.replaceChildren();
      try {
        const r = await api("POST", "/api/auth/login", { email: email.value, password: pw.value });
        state.user = r.user; state.csrf = r.csrfToken;
        location.hash = "#/documents";
      } catch (ex) { err.replaceChildren(errorBox(ex)); }
    },
  },
    h("div", { class: "field" }, h("label", { for: "email" }, "Email Address"), email),
    h("div", { class: "field" }, h("label", { for: "pw" }, "Password"), pw),
    err,
    h("button", { type: "submit", class: "btn-primary full-width" }, "Sign in to Vault"));

  render(h("div", { class: "login" },
    h("div", { class: "login-card" },
      h("div", { class: "login-header" },
        h("div", { class: "vault-badge-icon" }, "🛡️"),
        h("h1", null, "TrustVault"),
        h("p", { class: "login-subtitle" }, "Hardware-grade confidential document vault with immutable audit custody.")),
      form,
      h("div", { class: "demo-selector" },
        h("p", { class: "demo-heading" }, "Quick sign-in with demo accounts:"),
        h("div", { class: "demo-chips" },
          demoAccounts.map((acc) => h("button", {
            type: "button",
            class: "demo-chip",
            onclick: () => fill(acc),
          }, acc.label)))))));
}

// ---------------------------------------------------------------- documents list
async function viewDocuments(params) {
  const p = new URLSearchParams(params || "");
  const page = Number(p.get("page") || 1);
  const inputs = {
    q: h("input", { id: "q", type: "search", value: p.get("q") || "", placeholder: "Title or description" }),
    owner: h("input", { id: "owner", value: p.get("owner") || "", placeholder: "Name or email" }),
    category: h("select", { id: "category" }, h("option", { value: "" }, "Any"),
      state.categories.map((c) => h("option", { value: c, selected: p.get("category") === c }, c))),
    from: h("input", { id: "from", type: "date", value: p.get("from") || "" }),
    to: h("input", { id: "to", type: "date", value: p.get("to") || "" }),
    scope: h("select", { id: "scope" },
      [["all", "All I can open"], ["mine", "I own"], ["shared", "Shared with me"]].map(([v, l]) =>
        h("option", { value: v, selected: (p.get("scope") || "all") === v }, l))),
  };
  const search = (e) => {
    if (e) e.preventDefault();
    const q = new URLSearchParams();
    for (const [k, el] of Object.entries(inputs)) if (el.value) q.set(k, el.value);
    location.hash = "#/documents?" + q.toString();
  };
  const field = (id, label) => h("div", { class: "grow" }, h("label", { for: id }, label), inputs[id]);
  const form = h("form", { class: "sheet", onsubmit: search, role: "search" },
    h("div", { class: "row" }, field("q", "Name"), field("owner", "Owner"), field("category", "Category")),
    h("div", { class: "row", style: null },
      field("from", "Added from"), field("to", "Added to"), field("scope", "Show"),
      h("div", null, h("button", { type: "submit" }, "Search"))));

  const results = h("div", { class: "sheet" }, h("p", { class: "muted" }, "Loading…"));
  render(shell("documents", h("div", { class: "stack" },
    h("h1", null, "Documents"),
    state.user.role === "admin"
      ? h("p", { class: "muted" }, "Administrators only see documents someone has shared with them. Use Administration to oversee all activity.")
      : null,
    form, results)));

  try {
    p.set("page", page);
    const r = await api("GET", "/api/documents?" + p.toString());
    if (!r.documents.length) {
      results.replaceChildren(h("p", null, p.toString().length > 7
        ? "No documents match. Try fewer filters."
        : state.user.role === "owner" ? "Nothing here yet. Upload your first document." : "Nobody has shared a document with you yet."));
      return;
    }
    const rows = r.documents.map((d) => h("tr", {
      class: "clickable", tabindex: "0",
      onclick: () => { location.hash = "#/doc/" + d.id; },
      onkeydown: (e) => { if (e.key === "Enter") location.hash = "#/doc/" + d.id; },
    },
      h("td", null, h("strong", null, d.title), h("div", { class: "small muted" }, d.filename)),
      h("td", null, h("span", { class: "tag" }, d.category)),
      h("td", null, d.owner.name),
      h("td", null, levelMark(d.my_access)),
      h("td", { class: "small" }, fmtDate(d.created_at))));
    const pages = Math.max(1, Math.ceil(r.total / r.page_size));
    const go = (n) => { p.set("page", n); location.hash = "#/documents?" + p.toString(); };
    results.replaceChildren(
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Name", "Category", "Owner", "Your access", "Added"].map((t) => h("th", null, t)))),
        h("tbody", null, rows))),
      h("div", { class: "pager small muted" },
        h("button", { class: "quiet", disabled: page <= 1, onclick: () => go(page - 1) }, "Previous"),
        `Page ${page} of ${pages} · ${r.total} document${r.total === 1 ? "" : "s"}`,
        h("button", { class: "quiet", disabled: page >= pages, onclick: () => go(page + 1) }, "Next")));
  } catch (ex) { results.replaceChildren(errorBox(ex)); }
}

// ---------------------------------------------------------------- upload
function viewUpload() {
  const err = h("div");
  const title = h("input", { id: "title", required: true, maxlength: 200 });
  const desc = h("textarea", { id: "desc", maxlength: 2000 });
  const cat = h("select", { id: "cat" }, state.categories.map((c) => h("option", { value: c }, c)));
  const file = h("input", { id: "file", type: "file", required: true,
    accept: ".pdf,.png,.jpg,.jpeg,.txt,.csv,.md,.docx,.xlsx,.pptx" });
  file.addEventListener("change", () => {
    if (!title.value && file.files[0]) title.value = file.files[0].name.replace(/\.[^.]+$/, "");
  });
  const btn = h("button", { type: "submit" }, "Upload document");
  const form = h("form", {
    class: "sheet",
    onsubmit: async (e) => {
      e.preventDefault(); err.replaceChildren(); btn.disabled = true;
      const fd = new FormData();
      fd.append("title", title.value); fd.append("description", desc.value);
      fd.append("category", cat.value); fd.append("file", file.files[0]);
      try {
        const r = await api("POST", "/api/documents", fd, true);
        toast("Uploaded. Only you can see it until you share it.");
        location.hash = "#/doc/" + r.document.id;
      } catch (ex) { err.replaceChildren(errorBox(ex)); btn.disabled = false; }
    },
  },
    h("div", { class: "field" }, h("label", { for: "file" }, "File"), file,
      h("p", { class: "small muted" }, "PDF, image, text, CSV, Markdown or Office (no macros). Up to 10 MB.")),
    h("div", { class: "field" }, h("label", { for: "title" }, "Name"), title),
    h("div", { class: "field" }, h("label", { for: "cat" }, "Category"), cat),
    h("div", { class: "field" }, h("label", { for: "desc" }, "Description (optional)"), desc),
    err, btn);
  render(shell("upload", h("div", { class: "stack" }, h("h1", null, "Upload a document"),
    h("p", { class: "muted" }, "New documents are private to you. Nobody else can open one until you share it by name."),
    form)));
}

// ---------------------------------------------------------------- document detail
async function viewDocument(id) {
  render(shell("documents", h("p", { class: "muted" }, "Loading…")));
  let doc;
  try { doc = (await api("GET", "/api/documents/" + encodeURIComponent(id))).document; }
  catch (ex) { render(shell("documents", h("h1", null, "Document"), errorBox(ex), h("a", { href: "#/documents" }, "Back to documents"))); return; }

  const lvl = doc.my_access;
  const canEdit = lvl === "owner" || lvl === "edit";
  const isOwner = lvl === "owner";
  const dl = (v) => "/api/documents/" + doc.id + "/download" + (v ? "?version=" + v : "");

  const versions = h("div", { class: "table-wrap" }, h("table", null,
    h("thead", null, h("tr", null, ["Version", "File", "Uploaded", "SHA-256", ""].map((t) => h("th", null, t)))),
    h("tbody", null, doc.versions.map((v) => h("tr", null,
      h("td", null, "v" + v.version_no),
      h("td", null, v.filename, h("div", { class: "small muted" }, fmtSize(v.size_bytes))),
      h("td", { class: "small" }, fmtDate(v.created_at), h("div", { class: "muted" }, v.uploaded_by)),
      h("td", { class: "mono" }, v.sha256.slice(0, 16) + "…"),
      h("td", null, h("a", { class: "btn quiet", href: dl(v.version_no), download: "" }, "Download")))))));

  const left = h("div", { class: "stack" },
    h("div", { class: "sheet" },
      h("p", { class: "small muted" }, "Owned by " + doc.owner.name + " · " + doc.category),
      h("h1", null, doc.title),
      doc.description ? h("p", null, doc.description) : null,
      h("p", null, "Your access: ", levelMark(lvl)),
      h("div", { class: "row" },
        h("a", { class: "btn", href: dl(), download: "" }, "Download current version"),
        isOwner ? h("button", { class: "danger", onclick: () => deleteDoc(doc) }, "Move to trash") : null)),
    h("div", { class: "sheet" }, h("h2", null, "Versions"), versions),
    canEdit ? editPanel(doc) : null);

  const right = h("div", { class: "stack" });
  if (isOwner) {
    right.append(await sharingPanel(doc));
    right.append(await custodyPanel(doc));
  } else {
    right.append(h("div", { class: "sheet" }, h("h2", null, "Sharing"),
      h("p", { class: "muted" }, "Only the owner can see or change who has access to this document.")));
  }
  render(shell("documents", h("p", null, h("a", { href: "#/documents" }, "All documents")), h("div", { class: "split" }, left, right)));
}

function editPanel(doc) {
  const err = h("div");
  const title = h("input", { id: "etitle", value: doc.title, maxlength: 200 });
  const cat = h("select", { id: "ecat" }, state.categories.map((c) => h("option", { value: c, selected: c === doc.category }, c)));
  const desc = h("textarea", { id: "edesc", maxlength: 2000 }, doc.description);
  const file = h("input", { id: "vfile", type: "file" });
  return h("div", { class: "sheet" },
    h("h2", null, "Edit"),
    h("form", {
      onsubmit: async (e) => {
        e.preventDefault(); err.replaceChildren();
        try {
          await api("PATCH", "/api/documents/" + doc.id, { title: title.value, category: cat.value, description: desc.value });
          toast("Changes saved."); viewDocument(doc.id);
        } catch (ex) { err.replaceChildren(errorBox(ex)); }
      },
    },
      h("div", { class: "field" }, h("label", { for: "etitle" }, "Name"), title),
      h("div", { class: "field" }, h("label", { for: "ecat" }, "Category"), cat),
      h("div", { class: "field" }, h("label", { for: "edesc" }, "Description"), desc),
      h("button", { type: "submit", class: "quiet" }, "Save changes")),
    h("form", {
      onsubmit: async (e) => {
        e.preventDefault(); err.replaceChildren();
        if (!file.files[0]) return;
        const fd = new FormData(); fd.append("file", file.files[0]);
        try { await api("POST", "/api/documents/" + doc.id + "/versions", fd, true); toast("New version uploaded."); viewDocument(doc.id); }
        catch (ex) { err.replaceChildren(errorBox(ex)); }
      },
    },
      h("div", { class: "field", style: null }, h("label", { for: "vfile" }, "Upload a new version"), file),
      h("button", { type: "submit", class: "quiet" }, "Upload new version")),
    err);
}

async function deleteDoc(doc) {
  if (!confirm(`Move "${doc.title}" to the trash? Nobody, including you, can open it while it is there.`)) return;
  try { const r = await api("DELETE", "/api/documents/" + doc.id); toast(r.message); location.hash = "#/documents"; }
  catch (ex) { toast(ex.message, true); }
}

async function sharingPanel(doc) {
  const box = h("div", { class: "sheet" });
  const err = h("div");
  let data;
  try { data = await api("GET", `/api/documents/${doc.id}/grants`); }
  catch (ex) { box.append(errorBox(ex)); return box; }

  const list = data.grants.length
    ? h("table", null, h("tbody", null, data.grants.map((g) => h("tr", null,
        h("td", null, g.user.name, h("div", { class: "small muted" }, g.user.email),
          g.expires_at ? h("div", { class: "small " + (g.expired ? "error" : "muted") },
            (g.expired ? "Expired " : "Until ") + fmtDate(g.expires_at)) : null,
          g.source === "suggestion" ? h("div", { class: "small muted" }, "Added from a suggestion") : null),
        h("td", null, h("select", {
          "aria-label": "Access for " + g.user.name,
          onchange: async (e) => {
            try { await api("PATCH", `/api/documents/${doc.id}/grants/${g.id}`, { permission: e.target.value }); toast("Access changed."); }
            catch (ex) { toast(ex.message, true); }
          },
        }, ["read", "edit"].map((p) => h("option", { value: p, selected: g.permission === p }, p === "read" ? "Can read" : "Can edit")))),
        h("td", null, h("button", {
          class: "danger",
          onclick: async () => {
            if (!confirm(`Remove ${g.user.name}'s access? It stops working immediately.`)) return;
            try { await api("DELETE", `/api/documents/${doc.id}/grants/${g.id}`); toast("Access removed."); viewDocument(doc.id); }
            catch (ex) { toast(ex.message, true); }
          },
        }, "Remove"))))))
    : h("p", { class: "muted" }, "Only you can open this document.");

  // add someone
  const search = h("input", { id: "who", placeholder: "Search by name or email", autocomplete: "off" });
  const pick = h("select", { id: "pick", "aria-label": "Person" }, h("option", { value: "" }, "Type above to find people"));
  const perm = h("select", { id: "perm", "aria-label": "Access" }, h("option", { value: "read" }, "Can read"), h("option", { value: "edit" }, "Can edit"));
  const until = h("input", { id: "until", type: "date", "aria-label": "Access until (optional)" });
  let timer;
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        const r = await api("GET", "/api/users/directory?q=" + encodeURIComponent(search.value));
        pick.replaceChildren(...(r.users.length ? r.users.map((u) => h("option", { value: u.id }, `${u.name} (${u.email})`))
          : [h("option", { value: "" }, "No one found")]));
      } catch (ex) { toast(ex.message, true); }
    }, 250);
  });
  const add = h("form", {
    onsubmit: async (e) => {
      e.preventDefault(); err.replaceChildren();
      if (!pick.value) { err.replaceChildren(errorBox(new Error("Choose a person first."))); return; }
      try {
        await api("POST", `/api/documents/${doc.id}/grants`, { user_id: pick.value, permission: perm.value, expires_at: until.value || null });
        toast("Access granted."); viewDocument(doc.id);
      } catch (ex) { err.replaceChildren(errorBox(ex)); }
    },
  },
    h("div", { class: "field" }, h("label", { for: "who" }, "Share with a person"), search),
    h("div", { class: "row" },
      h("div", { class: "grow" }, pick), h("div", null, perm),
      h("div", null, until), h("div", null, h("button", { type: "submit" }, "Share"))),
    h("p", { class: "small muted" }, "Leave the date empty for access with no end date."));

  // suggestions
  const sugBox = h("div");
  const sugBtn = h("button", {
    class: "quiet",
    onclick: async () => {
      try {
        const r = await api("POST", `/api/documents/${doc.id}/suggestions`);
        if (!r.suggestions.length) { sugBox.replaceChildren(h("p", { class: "small muted" }, "No suggestions for this document.")); return; }
        sugBox.replaceChildren(h("p", { class: "small muted" }, r.note), ...r.suggestions.map((s) => h("div", { class: "alert info" },
          h("strong", null, `${s.user.name} (${s.user.email})`), h("span", { class: "small" }, s.reason),
          h("div", { class: "row" },
            h("button", { onclick: async () => {
              try { await api("POST", `/api/documents/${doc.id}/suggestions/${s.id}/accept`, { permission: "read" }); toast("Access granted."); viewDocument(doc.id); }
              catch (ex) { toast(ex.message, true); }
            } }, "Give read access"),
            h("button", { class: "quiet", onclick: async () => {
              try { await api("POST", `/api/documents/${doc.id}/suggestions/${s.id}/dismiss`); toast("Suggestion dismissed."); sugBox.replaceChildren(); }
              catch (ex) { toast(ex.message, true); }
            } }, "Dismiss")))));
      } catch (ex) { toast(ex.message, true); }
    },
  }, "Suggest people");

  box.append(h("h2", null, "Who has access"), list, h("hr", { style: null }), add, err,
    h("div", { class: "row" }, sugBtn), sugBox);
  return box;
}

const ACTION_LABEL = {
  "document.upload": "uploaded it", "document.download": "downloaded it", "document.read": "opened it",
  "document.update": "changed its details", "document.new_version": "uploaded a new version",
  "document.delete": "moved it to trash", "document.restore": "restored it", "document.edit": "tried to edit it",
  "document.share": "tried to manage access", "document.view_activity": "tried to view its record",
  "permission.grant": "gave access", "permission.change": "changed access", "permission.revoke": "removed access",
  "suggestion.shown": "was shown suggestions", "suggestion.accepted": "accepted a suggestion",
  "suggestion.dismissed": "dismissed a suggestion", "admin.ownership_transfer": "transferred ownership",
  "document.purge": "destroyed its content",
};

async function custodyPanel(doc) {
  const box = h("div", { class: "sheet" }, h("h2", null, "Custody record"));
  try {
    const r = await api("GET", `/api/documents/${doc.id}/activity`);
    if (!r.activity.length) { box.append(h("p", { class: "muted" }, "No activity yet.")); return box; }
    box.append(h("p", { class: "small muted" }, "Every access to this document, newest first. Refused attempts are in red."),
      h("div", { class: "custody" }, h("ol", null, r.activity.map((a) => {
        let detail = "";
        try { const d = JSON.parse(a.details); detail = d.grantee || (d.version ? "v" + d.version : "") || d.reason || ""; } catch (_) { /* ignore */ }
        const denied = a.outcome === "denied";
        return h("li", { class: denied ? "denied" : "" },
          h("div", { class: "when" }, fmtDate(a.ts)),
          (a.actor_email || "system") + " " + (denied ? "was refused: " : "") + (ACTION_LABEL[a.action] || a.action),
          detail ? h("span", { class: "small muted" }, " · " + detail) : null);
      }))));
  } catch (ex) { box.append(errorBox(ex)); }
  return box;
}

// ---------------------------------------------------------------- trash
async function viewTrash() {
  const box = h("div", { class: "sheet" }, h("p", { class: "muted" }, "Loading…"));
  render(shell("trash", h("div", { class: "stack" }, h("h1", null, "Trash"), box)));
  try {
    const r = await api("GET", "/api/documents/trash");
    if (!r.documents.length) { box.replaceChildren(h("p", null, "The trash is empty.")); return; }
    box.replaceChildren(h("p", { class: "muted" }, `Documents are destroyed ${r.retention_days} days after being moved here. Nobody can open them in the meantime.`),
      h("table", null, h("tbody", null, r.documents.map((d) => h("tr", null,
        h("td", null, h("strong", null, d.title), h("div", { class: "small muted" }, "Moved " + fmtDate(d.deleted_at))),
        h("td", null, h("button", { class: "quiet", onclick: async () => {
          try { await api("POST", `/api/documents/${d.id}/restore`); toast("Restored."); location.hash = "#/doc/" + d.id; }
          catch (ex) { toast(ex.message, true); }
        } }, "Restore")))))));
  } catch (ex) { box.replaceChildren(errorBox(ex)); }
}

// ---------------------------------------------------------------- account
function viewAccount() {
  const err = h("div");
  const cur = h("input", { id: "cur", type: "password", autocomplete: "current-password" });
  const nw = h("input", { id: "nw", type: "password", autocomplete: "new-password", minlength: 12 });
  render(shell("account", h("div", { class: "stack" }, h("h1", null, "Account"),
    h("form", {
      class: "sheet",
      onsubmit: async (e) => {
        e.preventDefault(); err.replaceChildren();
        try { await api("POST", "/api/auth/password", { current_password: cur.value, new_password: nw.value }); toast("Password changed. Your other sessions were signed out."); cur.value = nw.value = ""; }
        catch (ex) { err.replaceChildren(errorBox(ex)); }
      },
    },
      h("h2", null, "Change password"),
      h("div", { class: "field" }, h("label", { for: "cur" }, "Current password"), cur),
      h("div", { class: "field" }, h("label", { for: "nw" }, "New password (at least 12 characters)"), nw),
      err, h("button", { type: "submit" }, "Change password")))));
}

// ---------------------------------------------------------------- admin
async function viewAdmin(params) {
  const tab = new URLSearchParams(params || "").get("tab") || "alerts";
  const tabs = [["alerts", "Alerts"], ["audit", "Audit trail"], ["users", "Users"], ["documents", "Documents"]];
  const body = h("div", { class: "sheet" }, h("p", { class: "muted" }, "Loading…"));
  render(shell("admin", h("div", { class: "stack" }, h("h1", null, "Administration"),
    h("div", { class: "tabs", role: "tablist" }, tabs.map(([k, l]) => h("button", {
      role: "tab", "aria-selected": String(k === tab), onclick: () => { location.hash = "#/admin?tab=" + k; },
    }, l))), body)));
  try {
    if (tab === "alerts") await adminAlerts(body);
    else if (tab === "audit") await adminAudit(body, params);
    else if (tab === "users") await adminUsers(body);
    else await adminDocuments(body);
  } catch (ex) { body.replaceChildren(errorBox(ex)); }
}

async function adminAlerts(body) {
  const r = await api("GET", "/api/admin/alerts");
  const c = r.audit_chain;
  body.replaceChildren(
    h("p", null, "Audit trail integrity: ",
      c.valid ? h("span", { class: "chain-ok" }, `intact (${c.count} records)`)
              : h("span", { class: "chain-bad" }, `BROKEN at record ${c.broken_at}: ${c.reason}`)),
    c.valid ? h("p", { class: "small muted mono" }, "Head hash " + c.head_hash) : null,
    h("h2", null, "Worth a look"),
    r.alerts.length ? h("div", null, r.alerts.map((a) => h("div", { class: "alert " + a.severity },
      h("strong", null, a.title), h("span", { class: "small" }, a.detail))))
      : h("p", { class: "muted" }, "Nothing unusual in the last 24 hours."));
}

async function adminAudit(body, params) {
  const p = new URLSearchParams(params || "");
  p.delete("tab");
  const page = Number(p.get("page") || 1);
  const f = {
    actor: h("input", { id: "aactor", value: p.get("actor") || "", placeholder: "email" }),
    action: h("select", { id: "aaction" }, [["", "Any"], ["document.*", "Document activity"], ["document.download", "Downloads"],
      ["permission.*", "Permission changes"], ["auth.*", "Sign-ins"], ["admin.*", "Administrator actions"],
      ["suggestion.*", "Suggestions"], ["security.*", "Forged requests"]].map(([v, l]) =>
      h("option", { value: v, selected: (p.get("action") || "") === v }, l))),
    outcome: h("select", { id: "aoutcome" }, [["", "Any"], ["success", "Allowed"], ["denied", "Refused"]].map(([v, l]) =>
      h("option", { value: v, selected: (p.get("outcome") || "") === v }, l))),
    from: h("input", { id: "afrom", type: "date", value: p.get("from") || "" }),
    to: h("input", { id: "ato", type: "date", value: p.get("to") || "" }),
  };
  const apply = (e, pg) => {
    if (e) e.preventDefault();
    const q = new URLSearchParams({ tab: "audit" });
    for (const [k, el] of Object.entries(f)) if (el.value) q.set(k, el.value);
    if (pg) q.set("page", pg);
    location.hash = "#/admin?" + q.toString();
  };
  const fld = (id, l) => h("div", { class: "grow" }, h("label", { for: f[id].id }, l), f[id]);
  p.set("page", page); p.set("page_size", 50);
  const r = await api("GET", "/api/admin/audit?" + p.toString());
  const pages = Math.max(1, Math.ceil(r.total / r.page_size));
  body.replaceChildren(
    h("form", { onsubmit: apply },
      h("div", { class: "row" }, fld("actor", "Who"), fld("action", "What"), fld("outcome", "Result"),
        fld("from", "From"), fld("to", "To"), h("div", null, h("button", { type: "submit" }, "Filter")))),
    h("p", { class: "small" }, h("a", { href: "/api/admin/audit/export" }, "Export the full audit trail (JSON lines, with hashes)")),
    h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["#", "When", "Who", "Action", "Result", "Document / person", "Details"].map((t) => h("th", null, t)))),
      h("tbody", null, r.entries.map((e) => h("tr", { class: "outcome-" + e.outcome },
        h("td", { class: "small" }, e.seq),
        h("td", { class: "small" }, fmtDate(e.ts), h("div", { class: "muted" }, e.ip || "")),
        h("td", { class: "small" }, e.actor_email || "-"),
        h("td", { class: "small" }, e.action),
        h("td", { class: "small" }, e.outcome === "denied" ? "Refused" : e.outcome === "success" ? "Allowed" : e.outcome),
        h("td", { class: "small" }, e.document_title || (e.document_id ? e.document_id.slice(0, 8) + "…" : ""),
          e.target_email ? h("div", { class: "muted" }, "→ " + e.target_email) : null),
        h("td", { class: "mono" }, e.details === "{}" ? "" : e.details)))))),
    h("div", { class: "pager small muted" },
      h("button", { class: "quiet", disabled: page <= 1, onclick: () => apply(null, page - 1) }, "Previous"),
      `Page ${page} of ${pages} · ${r.total} records`,
      h("button", { class: "quiet", disabled: page >= pages, onclick: () => apply(null, page + 1) }, "Next")));
}

async function adminUsers(body) {
  const r = await api("GET", "/api/admin/users");
  const err = h("div");
  const nu = {
    name: h("input", { id: "nuname", required: true }), email: h("input", { id: "nuemail", type: "email", required: true }),
    role: h("select", { id: "nurole" }, ["viewer", "owner", "admin"].map((x) => h("option", { value: x }, x))),
    password: h("input", { id: "nupw", type: "password", required: true, minlength: 12, autocomplete: "new-password" }),
  };
  const act = async (fn, msg) => { try { await fn(); toast(msg); viewAdmin("tab=users"); } catch (ex) { toast(ex.message, true); } };
  body.replaceChildren(
    h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Person", "Role", "Status", ""].map((t) => h("th", null, t)))),
      h("tbody", null, r.users.map((u) => {
        const self = u.id === state.user.id;
        return h("tr", null,
          h("td", null, u.name, h("div", { class: "small muted" }, u.email)),
          h("td", null, self ? u.role : h("select", {
            "aria-label": "Role for " + u.name,
            onchange: (e) => act(() => api("PATCH", "/api/admin/users/" + u.id, { role: e.target.value }), "Role changed. Their sessions were ended."),
          }, ["viewer", "owner", "admin"].map((x) => h("option", { value: x, selected: x === u.role }, x)))),
          h("td", { class: "small" }, u.active ? "Active" : "Deactivated",
            u.locked_until && new Date(u.locked_until) > new Date() ? h("div", { class: "error" }, "Locked") : null),
          h("td", null, self ? h("span", { class: "small muted" }, "You") : h("div", { class: "row" },
            h("button", { class: u.active ? "danger" : "quiet",
              onclick: () => act(() => api("PATCH", "/api/admin/users/" + u.id, { active: !u.active }),
                u.active ? "Deactivated. Their sessions ended immediately." : "Reactivated.") }, u.active ? "Deactivate" : "Reactivate"),
            h("button", { class: "quiet", onclick: () => {
              const pw = prompt(`New password for ${u.email} (at least 12 characters):`);
              if (pw) act(() => api("POST", `/api/admin/users/${u.id}/reset-password`, { new_password: pw }), "Password reset. Their sessions were ended.");
            } }, "Reset password"),
            u.locked_until ? h("button", { class: "quiet", onclick: () => act(() => api("POST", `/api/admin/users/${u.id}/unlock`), "Unlocked.") }, "Unlock") : null)));
      })))),
    h("h2", null, "Add a person"),
    h("form", {
      onsubmit: (e) => {
        e.preventDefault(); err.replaceChildren();
        api("POST", "/api/admin/users", { name: nu.name.value, email: nu.email.value, role: nu.role.value, password: nu.password.value })
          .then(() => { toast("Account created."); viewAdmin("tab=users"); }).catch((ex) => err.replaceChildren(errorBox(ex)));
      },
    }, h("div", { class: "row" },
      h("div", { class: "grow" }, h("label", { for: "nuname" }, "Name"), nu.name),
      h("div", { class: "grow" }, h("label", { for: "nuemail" }, "Email"), nu.email),
      h("div", null, h("label", { for: "nurole" }, "Role"), nu.role),
      h("div", { class: "grow" }, h("label", { for: "nupw" }, "Initial password"), nu.password),
      h("div", null, h("button", { type: "submit" }, "Create account"))), err));
}

async function adminDocuments(body) {
  const [r, users] = await Promise.all([api("GET", "/api/admin/documents"), api("GET", "/api/admin/users")]);
  const owners = users.users.filter((u) => u.role === "owner" && u.active);
  body.replaceChildren(
    h("p", { class: "muted" }, "Details only. Administrators cannot open or download documents that have not been shared with them."),
    h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Document", "Owner", "People with access", "State", "Transfer to"].map((t) => h("th", null, t)))),
      h("tbody", null, r.documents.map((d) => h("tr", null,
        h("td", null, d.title, h("div", { class: "small muted" }, d.category + " · v" + d.current_version)),
        h("td", { class: "small" }, d.owner_name, d.owner_active ? null : h("div", { class: "error" }, "Owner deactivated")),
        h("td", null, d.live_grants),
        h("td", { class: "small" }, d.purged_at ? "Destroyed" : d.deleted_at ? "In trash" : "Active"),
        h("td", null, d.purged_at ? "" : h("select", {
          "aria-label": "Transfer " + d.title,
          onchange: async (e) => {
            if (!e.target.value) return;
            if (!confirm("Transfer ownership? The current owner loses access. This is recorded and flagged.")) { e.target.value = ""; return; }
            try { await api("POST", `/api/admin/documents/${d.id}/transfer`, { new_owner_id: e.target.value }); toast("Ownership transferred."); viewAdmin("tab=documents"); }
            catch (ex) { toast(ex.message, true); e.target.value = ""; }
          },
        }, h("option", { value: "" }, "Choose…"), owners.filter((o) => o.email !== d.owner_email)
          .map((o) => h("option", { value: o.id }, o.name))))))))));
}

// ---------------------------------------------------------------- router
async function route() {
  const hash = location.hash || "#/documents";
  const [path, query] = hash.slice(1).split("?");
  if (!state.user && path !== "/login") {
    try { const r = await api("GET", "/api/auth/me"); state.user = r.user; state.csrf = r.csrfToken; }
    catch (_) { if (location.hash !== "#/login") location.hash = "#/login"; else viewLogin(); return; }
  }
  if (path === "/login") return state.user ? (location.hash = "#/documents") : viewLogin();
  if (path === "/documents") return viewDocuments(query);
  if (path === "/upload") return viewUpload();
  if (path === "/trash") return viewTrash();
  if (path === "/account") return viewAccount();
  if (path === "/admin") return viewAdmin(query);
  if (path.startsWith("/doc/")) return viewDocument(path.slice(5));
  location.hash = "#/documents";
}

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);
