const page = document.querySelector("#page");
const status = document.querySelector("#status");
const scanDialog = document.querySelector("#scan-dialog");
const packageDialog = document.querySelector("#package-dialog");
const projectName = document.querySelector("#project-name");
const nav = [...document.querySelectorAll("[data-view]")];
const state = { view: "overview", report: null, comparison: null, busy: false };
const pageSize = 40;
const assetLimits = { file: 8 * 1024 * 1024, total: 16 * 1024 * 1024, count: 200 };
const skip = new Set([".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", ".hg", "vendor"]);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function button(text, className, action) {
  const control = el("button", className, text);
  control.type = "button";
  control.addEventListener("click", action);
  return control;
}

function notice(message = "", error = false) {
  status.textContent = message;
  status.classList.toggle("error", error);
  status.hidden = !message;
}

async function request(url, data, asText = false) {
  const init = data === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data)
  };
  const response = await fetch(url, init);
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(typeof detail.detail === "string" ? detail.detail : `Request failed (${response.status}).`);
  }
  return asText ? response.text() : response.json();
}

async function task(message, action) {
  if (state.busy) return;
  state.busy = true;
  notice(message);
  try {
    const result = await action();
    notice(result);
  } catch (error) {
    notice(error.message, true);
  } finally {
    state.busy = false;
  }
}

function heading(title, detail, ...controls) {
  const head = el("header", "page-heading");
  const labels = el("div");
  labels.append(el("h1", "", title));
  if (detail) labels.append(el("p", "muted", detail));
  head.append(labels);
  if (controls.length) {
    const actions = el("div", "actions");
    actions.append(...controls);
    head.append(actions);
  }
  return head;
}

function badge(level, text = level) {
  return el("span", `badge ${["low", "moderate", "high", "critical"].includes(level) ? level : ""}`, text);
}

function metric(label, value, detail) {
  const item = el("article", "card metric");
  item.append(el("p", "", label), el("strong", "", value));
  item.append(typeof detail === "string" ? el("small", "", detail) : detail);
  return item;
}

function section(title, control) {
  const card = el("section", "card section");
  const header = el("header", "section-title");
  header.append(el("h2", "", title));
  if (control) header.append(control);
  card.append(header);
  return card;
}

function finding(item, packages) {
  const card = el("article", "finding");
  const title = el("div", "finding-title");
  title.append(badge(item.level), el("h3", "", item.title));
  if (packages.has(item.package_id)) {
    const pkg = packages.get(item.package_id);
    if (pkg.source) title.append(button(pkg.name, "link-button package-name", () => inspect(pkg)));
    else title.append(el("span", "package-name", pkg.name));
  }
  card.append(title, el("p", "", item.evidence), el("p", "muted", item.recommendation));
  if (item.reference) {
    const link = el("a", "", "View OSV advisory");
    link.href = item.reference;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    card.append(link);
  }
  return card;
}

function empty(text) {
  return el("p", "empty", text);
}

function warnings(items) {
  if (!items.length) return null;
  const list = el("ul", "warning-list");
  for (const item of items.slice(0, 20)) list.append(el("li", "", item));
  if (items.length > 20) list.append(el("li", "", `${items.length - 20} more in the JSON report.`));
  return list;
}

async function download(report, kind, format) {
  let contents;
  try {
    contents = format === "json" ? JSON.stringify(report, null, 2) : await request(`/api/export/${kind}`, report, true);
  } catch (error) {
    notice(error.message, true);
    return;
  }
  const url = URL.createObjectURL(new Blob([contents], { type: format === "json" ? "application/json" : "text/plain" }));
  const link = el("a");
  link.href = url;
  link.download = `chainwatch-${kind}.${format}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportsFor(report, kind) {
  return [
    button("Export JSON", "secondary", () => download(report, kind, "json")),
    button("Export TXT", "secondary", () => download(report, kind, "txt"))
  ];
}

function overview(report) {
  const { summary, coverage } = report;
  const packages = new Map(report.packages.map(pkg => [pkg.id, pkg]));
  page.append(heading("Project overview", report.project, ...exportsFor(report, "scan")));
  const metrics = el("div", "metrics");
  metrics.append(
    metric("Project risk", `${summary.score} / 100`, badge(summary.level)),
    metric("Dependencies", summary.dependencies, summary.ecosystems.join(" · ") || "No ecosystems detected"),
    metric("Transitive", summary.transitive, `${summary.direct} direct · ${summary.unclassified} unclassified`),
    metric("Findings", summary.finding_count, `${summary.severity_counts.critical || 0} critical · ${summary.severity_counts.high || 0} high`)
  );
  const columns = el("div", "columns");
  const priorities = section("Priority findings", button("View findings", "secondary", () => navigate("findings")));
  if (report.findings.length) priorities.append(...report.findings.slice(0, 4).map(item => finding(item, packages)));
  else priorities.append(empty("No findings in the checks that ran."));
  const checks = section("Scan coverage", badge("", coverage.online ? "Online" : "Offline"));
  const list = el("ul", "coverage-list");
  for (const [label, value] of [
    ["Manifests read", coverage.manifests.length], ["Exact versions checked by OSV", coverage.osv_versions],
    ["Package identities checked in registries", coverage.registry_packages],
    ["GitHub repositories checked", coverage.repositories]
  ]) {
    const row = el("li");
    row.append(el("span", "", label), el("strong", "", value));
    list.append(row);
  }
  checks.append(list);
  const notes = warnings(report.warnings);
  if (notes) checks.append(notes);
  columns.append(priorities, checks);
  page.append(metrics, columns);
  const evidence = Object.entries(summary.categories);
  if (evidence.length) {
    const breakdown = section("Highest scores by category");
    const tags = el("div", "actions");
    for (const [category, score] of evidence.sort((a, b) => b[1] - a[1])) tags.append(badge("", `${category} · ${score}`));
    breakdown.append(tags);
    page.append(breakdown);
  }
}

function table(headers, rows) {
  const card = el("div", "card table-scroll");
  const grid = el("table");
  const header = el("thead");
  const top = el("tr");
  for (const label of headers) {
    const cell = el("th", "", label);
    cell.scope = "col";
    top.append(cell);
  }
  header.append(top);
  const body = el("tbody");
  for (const values of rows) {
    const row = el("tr");
    for (const value of values) {
      const cell = el("td");
      cell.append(value ?? "—");
      row.append(cell);
    }
    body.append(row);
  }
  grid.append(header, body);
  card.append(grid);
  return card;
}

function paginate(target, items, renderItems, message, index = 0) {
  target.replaceChildren();
  if (!items.length) {
    target.append(empty(message));
    return;
  }
  const start = index * pageSize;
  target.append(renderItems(items.slice(start, start + pageSize)));
  if (items.length <= pageSize) return;
  const controls = el("div", "pagination");
  const previous = button("Previous", "secondary", () => paginate(target, items, renderItems, message, index - 1));
  const next = button("Next", "secondary", () => paginate(target, items, renderItems, message, index + 1));
  previous.disabled = index === 0;
  next.disabled = start + pageSize >= items.length;
  controls.append(previous, el("span", "muted", `${start + 1}–${Math.min(start + pageSize, items.length)} of ${items.length}`), next);
  target.append(controls);
}

function typeOf(pkg) {
  return pkg.application ? "Application" : pkg.direct ? "Direct" : pkg.depth ? "Transitive" : "Unclassified";
}

function inventory(report) {
  page.append(heading("Dependencies", `${report.summary.dependencies} dependency instances across discovered manifests`));
  const toolbar = el("div", "toolbar");
  const filter = el("input");
  filter.type = "search";
  filter.placeholder = "Search package or path";
  filter.setAttribute("aria-label", "Search dependencies");
  const type = el("select");
  type.setAttribute("aria-label", "Dependency type");
  for (const label of ["All types", "Direct", "Transitive", "Unclassified", "Application"]) type.append(el("option", "", label));
  toolbar.append(filter, type);
  const results = el("div");
  page.append(toolbar, results);

  function refresh() {
    const term = filter.value.trim().toLowerCase();
    const matches = report.packages.filter(pkg =>
      (type.selectedIndex === 0 || type.value === typeOf(pkg)) &&
      `${pkg.name} ${pkg.source} ${pkg.location} ${pkg.ecosystem}`.toLowerCase().includes(term)
    );
    paginate(results, matches, items => table(
      ["Package", "Version", "Ecosystem", "Type", "Depth", "Risk"],
      items.map(pkg => [
        button(pkg.name, "link-button", () => inspect(pkg)), pkg.version ?? pkg.spec ?? "—", pkg.ecosystem,
        typeOf(pkg), pkg.depth === null ? "—" : String(pkg.depth), badge(pkg.level, `${pkg.score} · ${pkg.level}`)
      ])
    ), "No dependencies match these filters.");
  }
  filter.addEventListener("input", refresh);
  type.addEventListener("change", refresh);
  refresh();
}

function inspect(pkg) {
  const holder = document.querySelector("#package-details");
  const title = el("div", "dialog-heading");
  const close = button("×", "icon-button", () => packageDialog.close());
  close.setAttribute("aria-label", "Close package details");
  title.append(el("h2", "", pkg.name), close);
  const details = el("dl", "package-info");
  const properties = {
    "Ecosystem": pkg.ecosystem, "Type": typeOf(pkg), "Resolved version": pkg.version,
    "Declared range": pkg.spec, "Source": pkg.source, "Graph location": pkg.location,
    "Registry host": pkg.registry, "First publication": pkg.first_publish, "Latest release": pkg.last_publish,
    "OSV coverage": pkg.application ? "Application" : pkg.osv_checked ? "Checked" : "Unavailable or skipped"
  };
  if (pkg.repository) {
    const link = el("a", "", pkg.repository);
    link.href = pkg.repository;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    properties.Repository = link;
  }
  for (const [name, value] of Object.entries(properties)) {
    if (value === null) continue;
    const field = el("dd");
    field.append(value);
    details.append(el("dt", "", name), field);
  }
  const items = state.report.findings.filter(item => item.package_id === pkg.id);
  holder.replaceChildren(title, badge(pkg.level, `Risk ${pkg.score}/100 · ${pkg.level}`), details, el("h3", "", "Findings"));
  if (items.length) holder.append(...items.map(item => finding(item, new Map())));
  else holder.append(empty("No findings are listed for this package."));
  packageDialog.showModal();
}

function findings(report) {
  const packages = new Map(report.packages.map(pkg => [pkg.id, pkg]));
  page.append(heading("Findings", `${report.summary.finding_count} findings across the checks that ran`, ...exportsFor(report, "scan")));
  const toolbar = el("div", "toolbar");
  const filter = el("select");
  filter.setAttribute("aria-label", "Finding severity");
  for (const level of ["All severities", "critical", "high", "moderate", "low"]) filter.append(el("option", "", level));
  toolbar.append(filter);
  const results = el("div");
  page.append(toolbar, results);
  function refresh() {
    const filtered = report.findings.filter(item => filter.selectedIndex === 0 || item.level === filter.value);
    paginate(results, filtered, items => {
      const card = el("section", "card section");
      card.append(...items.map(item => finding(item, packages)));
      return card;
    }, "No findings match the selected severity.");
  }
  filter.addEventListener("change", refresh);
  refresh();
}

function graph(report) {
  page.append(heading("Dependency graph", "Follow paths from the project to direct and transitive dependencies."));
  const card = el("section", "card graph-card");
  const tools = el("div", "graph-tools");
  const canvas = el("canvas");
  canvas.setAttribute("aria-label", "Dependency graph. Use the package selector to focus a node.");
  const select = el("select");
  select.setAttribute("aria-label", "Focus a graph node");
  const colors = { critical: "#b62045", high: "#b74e31", moderate: "#986009", low: "#28785b" };
  const allPackages = new Map(report.packages.map(pkg => [pkg.id, pkg]));
  const incoming = new Map();
  for (const edge of report.edges) {
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    incoming.get(edge.to).push(edge.from);
  }
  const shown = new Map([[report.root, { id: report.root, name: report.project, depth: 0 }]]);
  const graphLimit = 240;
  for (const pkg of report.packages) {
    if (shown.size >= graphLimit + 1) break;
    const chain = [pkg];
    let current = pkg;
    while (current.depth > 1) {
      current = (incoming.get(current.id) || []).map(id => allPackages.get(id))
        .find(parent => parent && parent.depth === current.depth - 1);
      if (!current || shown.has(current.id)) break;
      chain.push(current);
    }
    for (const member of chain.reverse()) {
      if (shown.size >= graphLimit + 1) break;
      shown.set(member.id, member);
    }
  }
  const links = report.edges.filter(edge => shown.has(edge.from) && shown.has(edge.to));
  const columns = new Map();
  const deepest = Math.max(0, ...[...shown.values()].map(node => node.depth ?? 0));
  for (const node of shown.values()) {
    const depth = node.depth ?? deepest + 1;
    if (!columns.has(depth)) columns.set(depth, []);
    columns.get(depth).push(node);
  }
  const colWidth = 220;
  const boxWidth = 158;
  const boxHeight = 30;
  const rowHeight = 44;
  let imageWidth = 0;
  let imageHeight = 0;
  const coordinates = new Map();
  for (const [depth, nodes] of columns) {
    imageWidth = Math.max(imageWidth, depth * colWidth + boxWidth);
    imageHeight = Math.max(imageHeight, (nodes.length - 1) * rowHeight + boxHeight);
  }
  for (const [depth, nodes] of columns) {
    const top = (imageHeight - ((nodes.length - 1) * rowHeight + boxHeight)) / 2;
    nodes.forEach((node, index) => coordinates.set(node.id, {
      node, x: depth * colWidth, y: top + index * rowHeight
    }));
  }

  let scale = 1;
  let x = 0;
  let y = 0;
  let selected = report.root;
  let pointer = null;
  const ctx = canvas.getContext("2d");
  const detailsButton = button("Inspect package", "secondary", () => {
    const pkg = allPackages.get(selected);
    if (pkg) inspect(pkg);
  });
  detailsButton.disabled = true;
  for (const node of [...shown.values()].sort((a, b) => a.id === report.root ? -1 : b.id === report.root ? 1 : a.name.localeCompare(b.name))) {
    const option = el("option", "", node.id === report.root ? report.project : `${node.name} · ${node.version || node.ecosystem}`);
    option.value = node.id;
    select.append(option);
  }
  select.value = selected;

  function draw() {
    if (!canvas.isConnected || !ctx) return;
    const pixelRatio = window.devicePixelRatio || 1;
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    canvas.width = width * pixelRatio;
    canvas.height = height * pixelRatio;
    ctx.setTransform(pixelRatio * scale, 0, 0, pixelRatio * scale, pixelRatio * x, pixelRatio * y);
    ctx.lineWidth = 1.5;
    for (const link of links) {
      const a = coordinates.get(link.from);
      const b = coordinates.get(link.to);
      const start = a.x + boxWidth;
      const end = b.x;
      const mid = (start + end) / 2;
      ctx.strokeStyle = link.from === selected || link.to === selected ? "#5a5ddb" : "#c5cde2";
      ctx.beginPath();
      ctx.moveTo(start, a.y + boxHeight / 2);
      ctx.bezierCurveTo(mid, a.y + boxHeight / 2, mid, b.y + boxHeight / 2, end, b.y + boxHeight / 2);
      ctx.stroke();
    }
    ctx.font = "600 12px system-ui";
    ctx.textBaseline = "middle";
    for (const [id, point] of coordinates) {
      const root = id === report.root;
      const color = root ? "#353ab8" : colors[point.node.level];
      ctx.fillStyle = root ? "#353ab8" : "#ffffff";
      ctx.strokeStyle = id === selected ? "#4c4ad7" : "#c5cde2";
      ctx.lineWidth = id === selected ? 2.5 : 1;
      ctx.beginPath();
      ctx.roundRect(point.x, point.y, boxWidth, boxHeight, 7);
      ctx.fill();
      ctx.stroke();
      if (!root) {
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(point.x + 12, point.y + boxHeight / 2, 3, 0, Math.PI * 2);
        ctx.fill();
      }
      const name = point.node.name.length > 20 ? point.node.name.slice(0, 19) + "…" : point.node.name;
      ctx.fillStyle = root ? "#ffffff" : "#192238";
      ctx.fillText(name, point.x + (root ? 10 : 21), point.y + boxHeight / 2, boxWidth - 28);
    }
  }

  function fit() {
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    scale = Math.max(.05, Math.min(1.25, (width - 28) / imageWidth, (height - 28) / imageHeight));
    x = (width - scale * imageWidth) / 2;
    y = (height - scale * imageHeight) / 2;
    draw();
  }

  function zoom(multiplier, px = canvas.clientWidth / 2, py = canvas.clientHeight / 2) {
    const updated = Math.max(.05, Math.min(3, scale * multiplier));
    x = px - (px - x) * updated / scale;
    y = py - (py - y) * updated / scale;
    scale = updated;
    draw();
  }

  function focus(id, center) {
    selected = id;
    select.value = id;
    detailsButton.disabled = id === report.root;
    if (center) {
      const point = coordinates.get(id);
      scale = Math.max(scale, .8);
      x = canvas.clientWidth / 2 - (point.x + boxWidth / 2) * scale;
      y = canvas.clientHeight / 2 - (point.y + boxHeight / 2) * scale;
    }
    draw();
  }

  select.addEventListener("change", () => focus(select.value, true));
  canvas.addEventListener("wheel", event => {
    event.preventDefault();
    zoom(event.deltaY < 0 ? 1.16 : 1 / 1.16, event.offsetX, event.offsetY);
  }, { passive: false });
  canvas.addEventListener("pointerdown", event => {
    if (event.button !== 0) return;
    pointer = { x: event.offsetX, y: event.offsetY, startX: x, startY: y };
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener("pointermove", event => {
    if (!pointer) return;
    x = pointer.startX + event.offsetX - pointer.x;
    y = pointer.startY + event.offsetY - pointer.y;
    draw();
  });
  canvas.addEventListener("pointercancel", () => { pointer = null; });
  canvas.addEventListener("pointerup", event => {
    if (pointer && Math.hypot(event.offsetX - pointer.x, event.offsetY - pointer.y) < 5) {
      const px = (event.offsetX - x) / scale;
      const py = (event.offsetY - y) / scale;
      const match = [...coordinates.values()].find(point =>
        px >= point.x && py >= point.y && px <= point.x + boxWidth && py <= point.y + boxHeight
      );
      if (match) focus(match.node.id, false);
    }
    pointer = null;
  });
  const smaller = button("−", "icon-button", () => zoom(1 / 1.25));
  smaller.setAttribute("aria-label", "Zoom out");
  const larger = button("+", "icon-button", () => zoom(1.25));
  larger.setAttribute("aria-label", "Zoom in");
  tools.append(select, detailsButton, smaller, larger, button("Fit graph", "secondary", fit));
  const count = shown.size - 1;
  const footer = count < report.packages.length
    ? `Showing ${count} of ${report.packages.length} nodes, prioritizing risk and its paths. Export JSON for the full graph.`
    : `${count} package nodes · ${links.length} edges · Drag to pan and scroll to zoom.`;
  card.append(tools, canvas, el("p", "muted graph-footer", footer));
  page.append(card);
  fit();
  const observer = new ResizeObserver(fit);
  observer.observe(canvas);
  return () => observer.disconnect();
}

async function manifests(input) {
  const files = [...input.files].filter(file => {
    const path = file.webkitRelativePath.split("/").slice(1);
    if (!path.length || path.length > 13 || path.some(part => skip.has(part))) return false;
    return /^(?:package\.json|package-lock\.json|requirements(?:-.+)?\.txt)$/.test(file.name);
  });
  if (!files.length) throw new Error("Choose a folder containing supported dependency manifests.");
  if (files.length > assetLimits.count || files.some(file => file.size > assetLimits.file) ||
      files.reduce((sum, file) => sum + file.size, 0) > assetLimits.total) {
    throw new Error("The selected manifests exceed the scan size limit.");
  }
  const entries = await Promise.all(files.map(async file =>
    [file.webkitRelativePath.split("/").slice(1).join("/"), new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer())]
  ));
  return { name: files[0].webkitRelativePath.split("/")[0], files: Object.fromEntries(entries) };
}

function changes(report) {
  page.append(heading("Dependency changes", report ? `${report.before} → ${report.after}` : "Compare two project folders.",
    ...(report ? exportsFor(report, "comparison") : [])));
  const uploader = section("Compare snapshots");
  const form = el("form", "compare-form");
  const inputs = [];
  for (const text of ["Before folder", "After folder"]) {
    const label = el("label", "", text);
    const input = el("input");
    input.type = "file";
    input.setAttribute("webkitdirectory", "");
    input.multiple = true;
    input.required = true;
    inputs.push(input);
    label.append(input);
    form.append(label);
  }
  const submit = el("button", "primary", "Compare");
  submit.type = "submit";
  form.append(submit);
  form.addEventListener("submit", event => {
    event.preventDefault();
    task("Comparing manifests and dependency graphs…", async () => {
      submit.disabled = true;
      try {
        const [before, after] = await Promise.all(inputs.map(manifests));
        state.comparison = await request("/api/compare", { before, after });
        if (state.view === "changes") render();
        return "Comparison complete.";
      } finally {
        submit.disabled = false;
      }
    });
  });
  uploader.append(form);
  page.append(uploader);
  if (!report) return;
  const metrics = el("div", "metrics");
  const { summary } = report;
  metrics.append(
    metric("Change risk", `${summary.score} / 100`, badge(summary.level)),
    metric("Added", summary.added, "Dependency instances"),
    metric("Removed", summary.removed, "Dependency instances"),
    metric("Updated", summary.updated, "Including changed dependency paths")
  );
  metrics.classList.add("comparison-metrics");
  page.append(metrics);
  if (report.findings.length) {
    const packages = new Map(report.changes.map(change => [change.id, change]));
    const issues = section("Change findings");
    const results = el("div");
    paginate(results, report.findings, items => {
      const group = el("div");
      group.append(...items.map(item => finding(item, packages)));
      return group;
    }, "No change findings.");
    issues.append(results);
    page.append(issues);
  }
  const details = section("Changed dependencies");
  const entries = el("div");
  const version = state => state?.version ?? state?.spec ?? "—";
  paginate(entries, report.changes, items => table(
    ["Package", "Change", "Before", "After", "Reachability change"],
    items.map(change => [
      `${change.ecosystem} / ${change.name}`, change.kind, version(change.before), version(change.after),
      change.blast_radius ? `+${change.blast_radius.added} / −${change.blast_radius.removed} / ${change.blast_radius.updated} updated` : "—"
    ])
  ), "No dependency entries changed.");
  details.append(entries);
  const notes = warnings(report.warnings);
  if (notes) details.append(notes);
  page.append(details);
}

async function history() {
  page.append(heading("Scan history", "The local workspace keeps up to 20 recent scans."));
  const results = el("div");
  results.append(empty("Loading scan history…"));
  page.append(results);
  try {
    const rows = await request("/api/history");
    if (!results.isConnected) return;
    if (!rows.length) {
      results.replaceChildren(empty("Run a project scan to start your history."));
      return;
    }
    results.replaceChildren(table(["Project", "Scanned", "Risk"], rows.map(row => [
      button(row.name, "link-button", () => task("Opening saved scan…", async () => {
        state.report = await request(`/api/history/${row.id}`);
        state.comparison = null;
        navigate("overview");
        return "";
      })),
      new Date(row.created_at.replace(" ", "T") + "Z").toLocaleString(),
      badge(row.level, `${row.score} · ${row.level}`)
    ])));
  } catch (error) {
    results.replaceChildren(empty(error.message));
  }
}

let cleanup = null;
function render() {
  cleanup?.();
  cleanup = null;
  page.replaceChildren();
  projectName.textContent = state.report?.project || "ChainWatch";
  if (state.view === "history") {
    history();
  } else if (state.view === "changes") {
    changes(state.comparison);
  } else if (!state.report) {
    page.append(heading("ChainWatch", "Start a scan to view your project's dependencies."));
  } else {
    const views = { overview, inventory, graph, findings };
    cleanup = views[state.view](state.report);
  }
}

function navigate(view) {
  state.view = view;
  for (const item of nav) {
    const active = item.dataset.view === view;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  render();
  page.focus();
}

for (const item of nav) item.addEventListener("click", () => navigate(item.dataset.view));
document.querySelector("#open-scan").addEventListener("click", () => scanDialog.showModal());
document.querySelector("#close-scan").addEventListener("click", () => scanDialog.close());

const form = document.querySelector("#scan-form");
form.addEventListener("submit", event => {
  event.preventDefault();
  if (state.busy) return;
  const submit = form.querySelector("[type=submit]");
  const inlineAlert = el("p", "status error");
  inlineAlert.setAttribute("role", "alert");
  form.querySelector("[role=alert]")?.remove();
  task("Scanning dependency manifests…", async () => {
    submit.disabled = true;
    try {
      const project = await manifests(document.querySelector("#scan-folder"));
      project.online = document.querySelector("#scan-online").checked;
      const { id, report } = await request("/api/scan", project);
      state.report = report;
      state.comparison = null;
      scanDialog.close();
      form.reset();
      navigate("overview");
      return id ? "Scan complete." : "Scan complete. The report exceeded the local history size limit.";
    } catch (error) {
      inlineAlert.textContent = error.message;
      form.append(inlineAlert);
      throw error;
    } finally {
      submit.disabled = false;
    }
  });
});

task("Loading the offline demo…", async () => {
  const { report, comparison } = await request("/api/demo");
  state.report = report;
  state.comparison = comparison;
  render();
  return "";
});
