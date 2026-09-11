"use strict";

const invoke = window.__TAURI__.core.invoke;

const POLL_MS = 1000;

const state = {
  config: null,
  selectedId: null,
  status: null,
  busy: false,
};

/* ------------------------------------------------------------------ utils */

const $ = (id) => document.getElementById(id);

function banner(message, kind = "info", timeout = 6000) {
  const el = $("banner");
  el.textContent = message;
  el.className = "banner" + (kind === "info" ? "" : ` ${kind}`);
  el.hidden = false;
  clearTimeout(banner._t);
  if (timeout) banner._t = setTimeout(() => { el.hidden = true; }, timeout);
}

/** Build an element with text set safely; never inject markup from data. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const parseLines = (text) =>
  text.split("\n").map((l) => l.trim()).filter(Boolean);

/* --------------------------------------------------------------- profiles */

function renderProfiles() {
  const list = $("profile-list");
  list.replaceChildren();

  if (!state.config || state.config.profiles.length === 0) {
    list.append(el("p", "hint", "No profiles — and that's fine. Everything is already covered."));
    $("profile-editor").hidden = true;
    return;
  }

  for (const profile of state.config.profiles) {
    const item = el("div", "profile-item" + (profile.id === state.selectedId ? " selected" : ""));
    const left = el("div");
    left.append(el("div", "pname", profile.name || profile.id));
    const count = profile.domains.length;
    left.append(el("div", "pmeta", count === 0
      ? "no domains yet"
      : `${count} domain${count === 1 ? "" : "s"}`));
    item.append(left);
    item.addEventListener("click", () => selectProfile(profile.id));
    list.append(item);
  }
}

function selectProfile(id) {
  state.selectedId = id;
  $("profile-editor").hidden = !id;
  const profile = state.config.profiles.find((p) => p.id === id);
  if (profile) {
    $("edit-name").value = profile.name || "";
    $("edit-domains").value = profile.domains.join("\n");
    $("edit-command").value = profile.launch_command || "";
    $("edit-args").value = (profile.launch_args || []).join(" ");
  }
  renderProfiles();
}

async function saveProfile() {
  const profile = state.config.profiles.find((p) => p.id === state.selectedId);
  if (!profile) return banner("Select a profile first.", "error");

  profile.name = $("edit-name").value.trim() || profile.id;
  profile.domains = parseLines($("edit-domains").value);
  const command = $("edit-command").value.trim();
  profile.launch_command = command || null;
  profile.launch_args = $("edit-args").value.trim().split(/\s+/).filter(Boolean);

  try {
    await invoke("save_config", { config: state.config });
    banner(`Saved "${profile.name}".`, "success");
    renderProfiles();
    if (state.status?.active && state.status.profile === profile.id) {
      banner(`Saved "${profile.name}". Restart protection for the new domains to take effect.`, "info", 9000);
    }
  } catch (e) {
    banner(`Could not save: ${e}`, "error", 0);
  }
}

async function addProfile() {
  const name = "New profile";
  let id = "profile";
  let n = 2;
  while (state.config.profiles.some((p) => p.id === id)) id = `profile-${n++}`;

  state.config.profiles.push({
    id, name, domains: [], launch_command: null, launch_args: [], notes: null,
  });
  await invoke("save_config", { config: state.config });
  selectProfile(id);
}

async function deleteProfile() {
  if (!state.selectedId) return;
  const profile = state.config.profiles.find((p) => p.id === state.selectedId);
  if (!confirm(`Delete profile "${profile?.name ?? state.selectedId}"?`)) return;

  state.config.profiles = state.config.profiles.filter((p) => p.id !== state.selectedId);
  await invoke("save_config", { config: state.config });
  state.selectedId = state.config.profiles[0]?.id ?? null;
  if (state.selectedId) selectProfile(state.selectedId);
  else { $("edit-name").value = ""; $("edit-domains").value = ""; }
  renderProfiles();
}

async function launchGame() {
  if (!state.selectedId) return banner("Select a profile first.", "error");
  if (!state.status?.active) {
    banner("DNS protection is not running — this would use your network's DNS.", "error", 8000);
    return;
  }
  try {
    banner(await invoke("launch_game", { profile: state.selectedId }), "success");
  } catch (e) {
    banner(String(e), "error", 0);
  }
}

/* ------------------------------------------------------------ protection */

async function toggleProtection() {
  if (state.busy) return;
  state.busy = true;
  const btn = $("toggle-btn");
  const wasActive = state.status?.active;

  btn.disabled = true;
  btn.textContent = wasActive ? "Stopping…" : "Waiting for authentication…";
  setPill("busy", wasActive ? "Stopping" : "Authenticating");

  try {
    const result = wasActive
      ? await invoke("stop_protection")
      : await invoke("start_protection", { profile: state.selectedId });
    banner(result.message, result.started || wasActive ? "success" : "info", 8000);
  } catch (e) {
    banner(String(e), "error", 0);
  } finally {
    state.busy = false;
    await refresh();
  }
}

function setPill(kind, text) {
  $("status-pill").className = `pill pill-${kind}`;
  $("status-text").textContent = text;
}

/* --------------------------------------------------------------- activity */

function renderStatus(status) {
  state.status = status;
  if (state.busy) return;

  const btn = $("toggle-btn");
  btn.disabled = false;

  if (status.active) {
    setPill("on", "Protected");
    btn.textContent = "Stop protection";
  } else {
    setPill("off", "Not protected");
    btn.textContent = "Start protection";
  }

  const doh = status.recent.filter((q) => q.route === "doh").length;
  $("stat-queries").textContent = status.queries_total;
  $("stat-cache").textContent = status.cache_entries;
  $("stat-doh").textContent = doh;
  $("stat-local").textContent = status.recent.length - doh;

  $("d-listen").textContent = status.listen || "—";
  $("d-pid").textContent = status.pid || "—";
  $("d-providers").textContent = status.providers.join(", ") || "—";
  $("d-upstreams").textContent = status.upstreams.join(", ") || "—";
  $("d-takeover").textContent = status.active
    ? (status.took_over_resolv_conf ? "redirected to the local proxy" : "untouched (--no-takeover)")
    : "untouched";
  $("d-profile").textContent = status.profile || "none";
  $("d-forced").textContent = status.forced_domains.join(", ") || "none";

  renderLog(status.recent);
}

function renderLog(entries) {
  const log = $("query-log");
  log.replaceChildren();

  if (!entries.length) {
    log.append(el("p", "empty", state.status?.active
      ? "Protection is running. Queries will appear here as they resolve."
      : "No queries yet. Start protection to see live resolution."));
    return;
  }

  for (const q of entries) {
    const row = el("div", "log-row");
    row.append(el("span", `tag tag-${q.route}`, q.route));
    row.append(el("span", "qname", q.name.replace(/\.$/, "")));

    const failed = q.outcome !== "NoError" && q.outcome !== "Forwarded";
    const answers = q.answers.length ? q.answers.join(", ") : q.outcome;
    row.append(el("span", failed ? "qans qfail" : "qans", answers));
    row.append(el("span", "qtime", `${q.elapsed_ms}ms`));
    log.append(row);
  }
}

/* ------------------------------------------------------------ diagnostics */

const VERDICT_CLASS = {
  healthy: "v-healthy",
  divergent_but_healthy: "v-healthy",
  dns_interference: "v-interference",
  blocked_beyond_dns: "v-blocked",
  resolution_failed: "v-failed",
  content_restriction_forced: "v-blocked",
};

const VERDICT_LABEL = {
  healthy: "Healthy",
  divergent_but_healthy: "Different answers, both work",
  dns_interference: "DNS interference detected",
  blocked_beyond_dns: "Blocked beyond DNS",
  resolution_failed: "Resolution failed",
  content_restriction_forced: "Content restriction forced",
};

async function runDiagnostic() {
  const domains = parseLines($("diag-input").value);
  if (!domains.length) return banner("Enter at least one domain.", "error");

  const btn = $("diag-run");
  btn.disabled = true;
  btn.textContent = "Testing…";
  $("diag-results").replaceChildren(el("p", "empty", "Resolving and probing…"));

  try {
    renderVerdicts(await invoke("run_diagnostic", { domains }));
  } catch (e) {
    $("diag-results").replaceChildren();
    banner(String(e), "error", 0);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run diagnostic";
  }
}

function renderVerdicts(verdicts) {
  const box = $("diag-results");
  box.replaceChildren();

  for (const v of verdicts) {
    const card = el("div", "verdict");
    card.append(el("h3", null, v.domain));

    const row = (label, value, cls) => {
      const r = el("div", "verdict-row");
      r.append(el("b", null, label));
      r.append(el("code", cls, value));
      card.append(r);
    };

    row("System DNS", v.isp_error ? `failed: ${v.isp_error}` : (v.isp_addresses.join(", ") || "no answer"),
        v.isp_error ? "v-blocked" : null);
    row("DoH", v.doh_error ? `failed: ${v.doh_error}` : (v.doh_addresses.join(", ") || "no answer"),
        v.doh_error ? "v-blocked" : null);
    row("Reachable", v.reachable.join(", ") || "none", v.reachable.length ? "v-healthy" : "v-blocked");
    if (v.unreachable.length) row("Dead", v.unreachable.join(", "), "v-blocked");
    if (v.restriction) row("Restriction", v.restriction, "v-interference");

    const conclusion = el("div", `conclusion ${VERDICT_CLASS[v.conclusion] ?? ""}`);
    conclusion.append(el("strong", null, VERDICT_LABEL[v.conclusion] ?? v.conclusion));
    conclusion.append(document.createTextNode(" — " + explain(v.conclusion)));
    card.append(conclusion);
    box.append(card);
  }
}

function explain(conclusion) {
  switch (conclusion) {
    case "healthy":
      return "your resolver and DoH agree, and the addresses accept connections. DNS is not the problem here.";
    case "divergent_but_healthy":
      return "different addresses, but both work. Normal for CDN-hosted domains.";
    case "dns_interference":
      return "your resolver failed or returned addresses that do not work, while DoH returned working ones. This is what the tool routes around — worth adding to a profile.";
    case "blocked_beyond_dns":
      return "both resolvers answered, but nothing connects. The block is at the IP or SNI level, and changing DNS will not fix it.";
    case "content_restriction_forced":
      return "a resolver returned a Google/YouTube content-restriction address — how a network forces SafeSearch or YouTube Restricted Mode.";
    case "resolution_failed":
      return "neither resolver returned an address. Check the domain spelling and your connection.";
    default:
      return "";
  }
}

/* ----------------------------------------------------------------- tunnel */

const fmtBytes = (n) =>
  n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;

let tunnelBusy = false;

async function refreshTunnel() {
  let t;
  try { t = await invoke("tunnel_status"); } catch (e) { return; }

  $("tunnel-config-state").textContent = t.config_present
    ? `Config ready: ${t.config_path}`
    : "No tunnel config yet — generate or import one below.";
  $("wgcf-missing").hidden = t.config_present || t.wgcf_installed;
  $("warp-generate").disabled = !t.wgcf_installed;
  $("warp-generate").textContent = t.config_present
    ? "Regenerate Cloudflare WARP config"
    : "Generate free Cloudflare WARP config";
  $("tunnel-endpoint").textContent = t.endpoint || "—";
  $("tunnel-traffic").textContent = t.up ? `↓ ${fmtBytes(t.rx_bytes)}  ↑ ${fmtBytes(t.tx_bytes)}` : "—";

  $("exit-check").disabled = !t.up;
  $("hdr-tunnel").className = `pill pill-${t.up ? "on" : "off"}`;
  $("ov-tunnel-pill").className = `pill pill-${t.up ? "on" : "off"}`;
  $("ov-tunnel-text").textContent = t.up ? "Tunnel up" : "Tunnel down";
  $("ov-tunnel-toggle").textContent = t.config_present ? (t.up ? "Stop tunnel" : "Start tunnel") : "Set up tunnel";
  $("hdr-tunnel-text").textContent = t.up ? "Tunnel up" : "Tunnel down";
  state.tunnelUp = t.up;
  if (!$("page-tunnel").hidden || !$("page-overview").hidden) renderTunnelApps();

  if (tunnelBusy) return;
  const toggle = $("tunnel-toggle");
  toggle.disabled = !t.config_present;
  toggle.textContent = t.up ? "Stop tunnel" : "Start tunnel";
  $("tunnel-pill").className = `pill pill-${t.up ? "on" : "off"}`;
  $("tunnel-text").textContent = t.up ? "Tunnel up" : "Tunnel down";
  toggle.dataset.up = t.up ? "1" : "";
}

async function tunnelAction(label, fn, confirmText) {
  if (confirmText && !confirm(confirmText)) return;
  tunnelBusy = true;
  $("tunnel-pill").className = "pill pill-busy";
  $("tunnel-text").textContent = label;
  try {
    banner(await fn(), "success", 8000);
  } catch (e) {
    banner(String(e), "error", 0);
  } finally {
    tunnelBusy = false;
    await refreshTunnel();
  }
}

function toggleTunnel() {
  const up = $("tunnel-toggle").dataset.up === "1";
  return up
    ? tunnelAction("Stopping…", () => invoke("tunnel_down"),
        "Stop the tunnel? Apps launched in it will switch back to your normal connection.")
    : tunnelAction("Authenticating…", () => invoke("tunnel_up"));
}

function generateWarp() {
  return tunnelAction("Generating…", () => invoke("tunnel_generate_warp"),
    "This registers a free account with Cloudflare WARP and accepts Cloudflare's " +
    "terms of service. Your tunnelled traffic will exit through Cloudflare. Continue?");
}

function importConfig() {
  const path = $("wg-import-path").value.trim();
  if (!path) return banner("Enter the path to a WireGuard .conf file.", "error");
  return tunnelAction("Importing…", () => invoke("tunnel_import_config", { path }));
}

async function launchTunnelled(app) {
  try { banner(await invoke("launch_in_tunnel", { app }), "success", 8000); }
  catch (e) { banner(String(e), "error", 0); }
  renderTunnelApps();
}

async function attachApp(name) {
  const ok = confirm(
    `Move the running ${name} into the tunnel without closing it?\n\n` +
    `Its open internet connections are reset so they reconnect through the tunnel: ` +
    `a page may reload, a download may restart, a game may briefly disconnect. ` +
    `Needs your password.`);
  if (!ok) return;
  try { banner(await invoke("attach_to_tunnel", { app: name }), "success", 9000); }
  catch (e) { banner(String(e), "error", 0); }
  renderTunnelApps();
}

async function renderTunnelApps() {
  let apps;
  try { apps = await invoke("tunnel_apps"); } catch (e) { return; }
  renderAppRows($("tunnel-apps"), apps, false);
  renderAppRows($("ov-apps"), apps, true);
  if (!$("page-tunnel").hidden) renderSuggestions();
}

function renderAppRows(box, apps, compact) {
  box.replaceChildren();
  if (!apps.length) box.append(el("p", "hint", compact ? "No apps yet." : "No apps yet. Add one below."));

  for (const a of apps) {
    const row = el("div", "app-row");
    row.append(el("span", "aname", a.name));
    if (a.flatpak && !compact) row.append(el("span", "tag tag-system", "flatpak"));

    let text = compact ? "" : a.command, cls = "astate";
    if (!a.installed) { text = compact ? "not found" : `${a.command} — not found`; cls += " warn"; }
    else if (a.running_inside) { text = "in tunnel"; cls += " on"; }
    else if (a.running_outside) { text = "outside tunnel"; cls += " warn"; }
    row.append(el("span", cls, text));

    if (a.running_outside) {
      const move = el("button", "btn btn-primary btn-sm", compact ? "Move in" : "Move into tunnel");
      move.disabled = !state.tunnelUp;
      move.title = state.tunnelUp ? "Keeps the app open" : "Start the tunnel first";
      move.addEventListener("click", () => attachApp(a.name));
      row.append(move);
    } else {
      const launch = el("button", "btn btn-sm", a.running_inside ? "Running" : "Launch");
      launch.disabled = !state.tunnelUp || !a.installed || a.running_inside;
      launch.title = state.tunnelUp ? "" : "Start the tunnel first";
      launch.addEventListener("click", () => launchTunnelled(a.name));
      row.append(launch);
    }

    if (!compact) {
      const remove = el("button", "btn btn-ghost btn-sm", "Remove");
      remove.addEventListener("click", () => removeTunnelApp(a.name));
      row.append(remove);
    }
    box.append(row);
  }
}

async function renderSuggestions() {
  let list;
  try { list = await invoke("suggest_apps"); } catch (e) { return; }
  const box = $("suggestions");
  box.replaceChildren();
  $("suggest-wrap").hidden = list.length === 0;
  for (const sug of list) {
    const chip = el("button", "chip", `+ ${sug.name}`);
    if (sug.command.startsWith("flatpak ")) chip.append(el("small", null, "flatpak"));
    chip.title = sug.command;
    chip.addEventListener("click", () => addTunnelAppFrom(sug.name, sug.command));
    box.append(chip);
  }
}

async function addTunnelAppFrom(name, commandLine) {
  const parts = commandLine.trim().split(/\s+/);
  if (state.config.tunnel_apps.some((a) => a.name === name)) {
    return banner(`There is already an app called "${name}".`, "error");
  }
  state.config.tunnel_apps.push({ name, command: parts[0], args: parts.slice(1), process: null });
  try {
    await invoke("save_config", { config: state.config });
    renderTunnelApps();
  } catch (e) { banner(`Could not save: ${e}`, "error", 0); }
}

async function addTunnelApp() {
  const name = $("app-name").value.trim();
  const command = $("app-command").value.trim();
  if (!name || !command) return banner("Give the app a name and a command.", "error");
  await addTunnelAppFrom(name, command);
  $("app-name").value = ""; $("app-command").value = "";
}

async function removeTunnelApp(name) {
  state.config.tunnel_apps = state.config.tunnel_apps.filter((a) => a.name !== name);
  try { await invoke("save_config", { config: state.config }); renderTunnelApps(); }
  catch (e) { banner(`Could not save: ${e}`, "error", 0); }
}

async function checkExit() {
  const btn = $("exit-check");
  btn.disabled = true; btn.textContent = "Checking…";
  try {
    const r = await invoke("tunnel_check_exit");
    $("exit-result").hidden = false;
    $("exit-direct").textContent = r.direct_ip ? `${r.direct_ip} (${r.direct_loc ?? "?"})` : "no response";
    $("exit-tunnel").textContent = r.tunnel_error ?? `${r.tunnel_ip} (${r.tunnel_loc ?? "?"})`;
    $("exit-warp").textContent = r.tunnel_warp ?? "—";
    if (r.tunnel_ip && r.tunnel_ip === r.direct_ip) {
      banner("The tunnel shows the same IP as your direct connection — traffic is NOT going through the tunnel.", "error", 0);
    }
  } catch (e) {
    banner(String(e), "error", 0);
  } finally {
    btn.disabled = false; btn.textContent = "Check exit IP";
  }
}

/* --------------------------------------------------------------- settings */

// Settings edit a draft of just the DNS fields, so saving can never clobber
// profiles or tunnel apps changed elsewhere in the meantime.
const clone = (o) => JSON.parse(JSON.stringify(o));
const pickSettings = (c) => ({ providers: clone(c.providers), policy: clone(c.policy) });
let presets = [];

function settingsDirty() {
  return state.draft && JSON.stringify(state.draft) !== JSON.stringify(pickSettings(state.config));
}

function updateSettingsState() {
  const dirty = settingsDirty();
  $("settings-save").disabled = !dirty;
  $("settings-revert").disabled = !dirty;
  $("settings-state").textContent = dirty ? "You have unsaved changes." : "No unsaved changes.";
  $("settings-state").classList.toggle("dirty", dirty);
}

function renderSettings() {
  if (!state.config) return;
  if (!state.draft) state.draft = pickSettings(state.config);
  const d = state.draft;

  const list = $("prov-list");
  list.replaceChildren();
  d.providers.forEach((p, i) => {
    const row = el("div", "app-row");
    row.append(el("span", "tag tag-system", String(i + 1)));
    row.append(el("span", "aname", p.name));
    row.append(el("span", "prov-url", p.url));
    const result = el("span", "prov-test", "");
    row.append(result);

    const up = el("button", "btn btn-ghost btn-sm btn-icon", "↑");
    up.disabled = i === 0;
    up.title = "Try earlier";
    up.addEventListener("click", () => { d.providers.splice(i - 1, 0, d.providers.splice(i, 1)[0]); renderSettings(); });
    const down = el("button", "btn btn-ghost btn-sm btn-icon", "↓");
    down.disabled = i === d.providers.length - 1;
    down.title = "Try later";
    down.addEventListener("click", () => { d.providers.splice(i + 1, 0, d.providers.splice(i, 1)[0]); renderSettings(); });
    const test = el("button", "btn btn-ghost btn-sm", "Test");
    test.addEventListener("click", () => testProvider(p, result, test));
    const remove = el("button", "btn btn-ghost btn-sm", "Remove");
    remove.disabled = d.providers.length === 1;
    remove.title = d.providers.length === 1 ? "At least one provider is required" : "";
    remove.addEventListener("click", () => { d.providers.splice(i, 1); renderSettings(); });
    row.append(up, down, test, remove);
    list.append(row);
  });

  const chips = $("prov-presets");
  chips.replaceChildren();
  const missing = presets.filter((pr) => !d.providers.some((p) => p.url === pr.url));
  $("preset-hint").hidden = missing.length === 0;
  for (const pr of missing) {
    const chip = el("button", "chip", `+ ${pr.name}`);
    if (pr.name === "AdGuard") chip.append(el("small", null, "blocks ads"));
    chip.title = pr.url;
    chip.addEventListener("click", () => { d.providers.push(clone(pr)); renderSettings(); });
    chips.append(chip);
  }

  if (document.activeElement !== $("set-force-doh")) $("set-force-doh").value = d.policy.force_doh.join("\n");
  if (document.activeElement !== $("set-force-local")) $("set-force-local").value = d.policy.force_local.join("\n");
  $("route-doh").checked = d.policy.default_doh;
  $("route-local").checked = !d.policy.default_doh;
  updateSettingsState();
}

async function testProvider(p, result, btn) {
  btn.disabled = true;
  result.className = "prov-test";
  result.textContent = "testing…";
  try {
    const r = await invoke("test_provider", { provider: p });
    result.className = `prov-test ${r.ok ? "ok" : "bad"}`;
    result.textContent = r.ok ? `✓ ${r.ms} ms` : "✗ failed";
    result.title = r.detail;
    return r.ok;
  } catch (e) {
    result.className = "prov-test bad";
    result.textContent = "✗ error";
    result.title = String(e);
    return false;
  } finally {
    btn.disabled = false;
  }
}

async function addCustomProvider() {
  const name = $("cp-name").value.trim();
  const url = $("cp-url").value.trim();
  const bootstrap = $("cp-boot").value.split(/[\s,]+/).filter(Boolean);
  if (!name || !url) return banner("A custom provider needs a name and a URL.", "error");
  if (!url.startsWith("https://")) return banner("The URL must start with https://", "error");
  if (!bootstrap.length) return banner("Add at least one bootstrap IP.", "error");

  const provider = { name, url, bootstrap };
  const btn = $("cp-add");
  btn.disabled = true; btn.textContent = "Testing…";
  try {
    const r = await invoke("test_provider", { provider });
    if (!r.ok) return banner(`${name} did not answer: ${r.detail}`, "error", 0);
    state.draft.providers.push(provider);
    $("cp-name").value = ""; $("cp-url").value = ""; $("cp-boot").value = "";
    banner(`${name} works (${r.ms} ms) and was added. Remember to save.`, "success");
    renderSettings();
  } catch (e) {
    banner(String(e), "error", 0);
  } finally {
    btn.disabled = false; btn.textContent = "Test & add";
  }
}

async function saveSettings() {
  const next = { ...clone(state.config), ...clone(state.draft) };
  try {
    await invoke("save_config", { config: next });
    state.config = next;
    state.draft = pickSettings(next);
    banner("Settings saved. They apply the next time DNS protection starts.", "success");
    $("settings-restart").hidden = !state.status?.active;
    renderSettings();
  } catch (e) {
    banner(`Not saved: ${e}`, "error", 0);
  }
}

async function restartProtection() {
  if (!confirm("Restart DNS protection to apply the new settings? You'll be asked for your password twice (stop, then start).")) return;
  const profile = state.status?.profile ?? null;
  try {
    await invoke("stop_protection");
    const r = await invoke("start_protection", { profile });
    banner(r.message, r.started ? "success" : "info", 8000);
    $("settings-restart").hidden = true;
  } catch (e) {
    banner(String(e), "error", 0);
  }
  refresh();
}

function wireSettings() {
  $("cp-add").addEventListener("click", addCustomProvider);
  $("settings-save").addEventListener("click", saveSettings);
  $("settings-revert").addEventListener("click", () => { state.draft = null; renderSettings(); });
  $("settings-restart").addEventListener("click", restartProtection);
  $("route-doh").addEventListener("change", () => { state.draft.policy.default_doh = true; updateSettingsState(); });
  $("route-local").addEventListener("change", () => { state.draft.policy.default_doh = false; updateSettingsState(); });
  $("set-force-doh").addEventListener("input", (e) => { state.draft.policy.force_doh = parseLines(e.target.value); updateSettingsState(); });
  $("set-force-local").addEventListener("input", (e) => { state.draft.policy.force_local = parseLines(e.target.value); updateSettingsState(); });
}

/* ---------------------------------------------------------- import + update */

async function importPickedFile(ev) {
  const file = ev.target.files?.[0];
  ev.target.value = "";
  if (!file) return;
  if (file.size > 64 * 1024) return banner("That file is too large to be a WireGuard config.", "error");
  const text = await file.text();
  return tunnelAction("Importing…", () => invoke("tunnel_import_text", { text }));
}

async function initUpdates() {
  let u;
  try { u = await invoke("update_info"); } catch (e) { return; }
  if (u.available) {
    $("upd-text").textContent = u.installed
      ? `Installed from ${u.source}. After changing the code, rebuild here.`
      : `Running a development build from ${u.source}. Rebuilding updates the launcher copy.`;
    $("upd-run").hidden = false;
  } else {
    $("upd-text").textContent = "The source folder (or cargo) isn't available, so this copy can't rebuild itself.";
  }
}

async function runUpdate() {
  if (!confirm("Rebuild Detour from source and reinstall it? This takes a couple of minutes. DNS protection and the tunnel keep running.")) return;
  const btn = $("upd-run");
  btn.disabled = true; btn.textContent = "Building… (a couple of minutes)";
  $("upd-text").textContent = "Compiling. You can keep using the app meanwhile.";
  try {
    $("upd-text").textContent = await invoke("rebuild_and_install");
    $("upd-restart").hidden = false;
  } catch (e) {
    $("upd-text").textContent = "Build failed — see the message above.";
    banner(String(e), "error", 0);
  } finally {
    btn.disabled = false; btn.textContent = "Rebuild & reinstall";
  }
}

/* --------------------------------------------------------- filter bypass */

let filterRunning = false;

async function refreshFilter() {
  let f;
  try { f = await invoke("filter_status"); } catch (e) { return; }
  filterRunning = f.running;
  $("ov-filter-pill").className = `pill pill-${f.running ? "on" : "off"}`;
  $("ov-filter-text").textContent = f.running
    ? `On · ${f.fragmented} split` : "Off";
  $("ov-filter-toggle").textContent = f.running ? "Stop filter bypass" : "Start filter bypass";
  $("filter-allapps").disabled = !f.running;
  renderFilterApps();
}

async function toggleFilter() {
  try {
    banner(await invoke(filterRunning ? "filter_stop" : "filter_start"), "success", 6000);
  } catch (e) { banner(String(e), "error", 0); }
  refreshFilter();
}

// Chromium-family browsers can take --proxy-server; others can't.
const CHROMIUM = ["brave", "brave-browser", "chromium", "google-chrome-stable",
                  "google-chrome", "vivaldi", "vivaldi-stable", "microsoft-edge"];

async function renderFilterApps() {
  let apps;
  try { apps = await invoke("tunnel_apps"); } catch (e) { return; }
  const box = $("ov-filter-apps");
  box.replaceChildren();
  const browsers = apps.filter((a) => CHROMIUM.includes(a.command.split("/").pop()));
  if (!browsers.length) {
    box.append(el("p", "hint", "Add a Chromium-family browser (Brave, Chrome…) to launch it here."));
    return;
  }
  for (const a of browsers) {
    const row = el("div", "app-row");
    row.append(el("span", "aname", a.name));
    row.append(el("span", "astate", a.installed ? "" : "not found"));
    const btn = el("button", "btn btn-sm", "Launch");
    btn.disabled = !filterRunning || !a.installed;
    btn.title = filterRunning ? "Quit the browser first if it's open" : "Start filter bypass first";
    btn.addEventListener("click", () => launchFilter(a.name));
    row.append(btn);
    box.append(row);
  }
}

async function toggleAllApps(ev) {
  const want = ev.target.checked;
  ev.target.disabled = true;
  try {
    banner(await invoke(want ? "filter_route_on" : "filter_route_off"), "success", 8000);
  } catch (e) {
    banner(String(e), "error", 0);
    ev.target.checked = !want;   // reflect that it did not take effect
  } finally {
    ev.target.disabled = false;
  }
}

async function launchFilter(app) {
  try { banner(await invoke("launch_with_filter", { app }), "success", 8000); }
  catch (e) { banner(String(e), "error", 0); }
}

/* ------------------------------------------------------------------- boot */

function wireNav() {
  for (const item of document.querySelectorAll(".nav-item")) {
    item.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("nav-active"));
      item.classList.add("nav-active");
      for (const page of document.querySelectorAll(".page")) {
        page.hidden = page.id !== `page-${item.dataset.page}`;
      }
      if (item.dataset.page === "tunnel" || item.dataset.page === "overview") refreshTunnel();
      if (item.dataset.page === "settings") renderSettings();
    });
  }
}

async function refresh() {
  try {
    renderStatus(await invoke("get_status"));
  } catch (e) {
    console.error("status poll failed", e);
  }
}

async function init() {
  wireNav();
  $("toggle-btn").addEventListener("click", toggleProtection);
  $("save-profile").addEventListener("click", saveProfile);
  $("add-profile").addEventListener("click", addProfile);
  $("delete-profile").addEventListener("click", deleteProfile);
  $("launch-btn").addEventListener("click", launchGame);
  $("diag-run").addEventListener("click", runDiagnostic);
  $("tunnel-toggle").addEventListener("click", toggleTunnel);
  $("warp-generate").addEventListener("click", generateWarp);
  $("wg-import").addEventListener("click", importConfig);
  $("app-add").addEventListener("click", addTunnelApp);
  $("wg-pick").addEventListener("click", () => $("wg-file").click());
  $("wg-file").addEventListener("change", importPickedFile);
  $("upd-run").addEventListener("click", runUpdate);
  $("upd-restart").addEventListener("click", () => invoke("restart_app"));
  wireSettings();
  const goTunnel = () => document.querySelector('[data-page="tunnel"]').click();
  document.querySelector(".link-tunnel").addEventListener("click", goTunnel);
  $("ov-tunnel-toggle").addEventListener("click", () =>
    $("tunnel-toggle").disabled ? goTunnel() : toggleTunnel());
  $("exit-check").addEventListener("click", checkExit);
  $("ov-filter-toggle").addEventListener("click", toggleFilter);
  $("filter-allapps").addEventListener("change", toggleAllApps);

  try {
    state.config = await invoke("get_config");
    $("d-config").textContent = await invoke("get_config_path");
    presets = await invoke("provider_presets");
    initUpdates();
    if (state.config.profiles.length) selectProfile(state.config.profiles[0].id);
    else $("profile-editor").hidden = true;
    renderProfiles();
  } catch (e) {
    banner(`Could not load config: ${e}`, "error", 0);
  }

  if (!(await invoke("helper_available"))) {
    banner("The dns-helper binary was not found. Build it with: cargo build -p dns-helper", "error", 0);
    $("toggle-btn").disabled = true;
  }

  await refresh();
  await refreshTunnel();
  await refreshFilter();
  setInterval(refresh, POLL_MS);
  setInterval(refreshTunnel, 2000);
  setInterval(refreshFilter, 2000);
}

document.addEventListener("DOMContentLoaded", init);
