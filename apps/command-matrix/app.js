/**
 * TrustWeave Command Matrix — renderer.
 *
 * All heavy lifting happens inside the Rust engine and reaches this page only
 * through Tauri IPC. This file owns three jobs: route a dropped path to the
 * correct engine command, paint the results (Merkle-DAG canvas, radar sweep,
 * threat pins), and keep the console honest about what actually ran.
 */
(() => {
  "use strict";

  // ── DOM ──────────────────────────────────────────────────────────────────
  const tabs = [...document.querySelectorAll(".mode-tab")];
  const vault = document.querySelector(".vault-stage");
  const panel = document.querySelector("#vault-panel");
  const overlay = document.querySelector("#drag-overlay");
  const overlayLabel = document.querySelector("#drag-overlay-label");
  const stageLabel = document.querySelector("#stage-mode-label");
  const stageState = document.querySelector("#stage-mode-state");
  const stageFooterMid = document.querySelector("#stage-footer-mid");
  const vaultOverline = document.querySelector("#vault-overline");
  const vaultTitle = document.querySelector("#vault-title");
  const vaultDescription = document.querySelector("#vault-description");
  const workspaceState = document.querySelector("#workspace-state");
  const resultState = document.querySelector("#result-state");
  const resultContent = document.querySelector("#result-content");
  const summary = document.querySelector("#summary-grid");
  const credentialRow = document.querySelector("#credential-row");
  const credKind = document.querySelector("#cred-kind");
  const credPath = document.querySelector("#cred-path");
  const copyButton = document.querySelector("#copy-hash");
  const copyLabel = document.querySelector("#copy-hash-label");
  const threatList = document.querySelector("#threat-list");
  const threatMarkers = document.querySelector("#threat-markers");
  const canvas = document.querySelector("#merkle-canvas");
  const terminalBody = document.querySelector("#terminal-body");
  const terminalStatus = document.querySelector("#terminal-status");
  const scannerState = document.querySelector("#scanner-state");
  const scannerNote = document.querySelector("#scanner-note");
  const scannerMetric = document.querySelector("#scanner-metric");
  const threatLock = document.querySelector("#threat-lock");
  const engineVersion = document.querySelector("#engine-version");
  const footerCapability = document.querySelector("#footer-capability");
  const aboutDialog = document.querySelector("#about-dialog");
  const toast = document.querySelector("#toast");

  // ── State ────────────────────────────────────────────────────────────────
  let mode = "ledger";
  let busy = false;
  let clipboardHash = "";
  let scannerLinked = false;
  let toastTimer;
  let merkleAnimation = 0;
  let lastMerkleView = null;

  const tauri = window.__TAURI__;
  const core = tauri && tauri.core;
  const events = tauri && tauri.event;
  const hasCore = Boolean(core && typeof core.invoke === "function");

  // ── Small helpers ────────────────────────────────────────────────────────
  const now = () => new Date().toLocaleTimeString("en-GB", { hour12: false });

  function formatBytes(value) {
    if (!Number.isFinite(value)) return "—";
    if (value < 1024) return `${value} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let size = value;
    let unit = -1;
    do {
      size /= 1024;
      unit += 1;
    } while (size >= 1024 && unit < units.length - 1);
    return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit]}`;
  }

  const basename = (path) => String(path).split(/[\\/]/).filter(Boolean).pop() || path;

  function announce(message, state = "READY", type = "") {
    resultContent.className = `result-content${type ? ` ${type}` : ""}`;
    resultContent.innerHTML = "";
    const time = document.createElement("span");
    time.className = "feed-time";
    time.textContent = now();
    const text = document.createElement("span");
    text.className = "feed-message";
    text.textContent = message;
    resultContent.append(time, text);
    resultState.textContent = state;
  }

  function notify(message) {
    toast.textContent = message;
    toast.classList.add("visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 2800);
  }

  function setWorkspaceState(text) {
    workspaceState.textContent = text;
  }

  // ── Console ──────────────────────────────────────────────────────────────
  function logLine(text, kind = "") {
    const line = document.createElement("div");
    line.className = `term-line${kind ? ` ${kind}` : ""}`;
    const stamp = document.createElement("span");
    stamp.className = "term-stamp";
    stamp.textContent = now();
    const body = document.createElement("span");
    body.className = "term-text";
    body.textContent = text;
    line.append(stamp, body);
    terminalBody.append(line);
    terminalBody.scrollTop = terminalBody.scrollHeight;
    while (terminalBody.childElementCount > 240) terminalBody.firstElementChild.remove();
  }

  function clearConsole() {
    terminalBody.innerHTML = "";
  }

  function setTerminalStatus(text, kind = "") {
    terminalStatus.textContent = text;
    terminalStatus.className = kind;
  }

  // ── Canvas sizing ────────────────────────────────────────────────────────
  function fitCanvas() {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.round(rect.width * dpr));
    canvas.height = Math.max(1, Math.round(rect.height * dpr));
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, width: rect.width, height: rect.height };
  }

  function clearCanvas() {
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    cancelAnimationFrame(merkleAnimation);
    merkleAnimation = 0;
    lastMerkleView = null;
  }

  /**
   * Render the Merkle-DAG bottom-up (leaves → root) with a progressive reveal
   * so nodes light up layer by layer. Geometry comes straight from the engine's
   * `build_merkle` levels, so the drawn topology is the real hash topology.
   * Layout is measured once; only the reveal alpha changes per frame.
   */
  function drawMerkle(view) {
    const levels = Array.isArray(view.levels) ? view.levels : [];
    if (levels.length === 0) return;

    lastMerkleView = view;
    cancelAnimationFrame(merkleAnimation);
    vault.classList.add("merkle-active");
    stageFooterMid.textContent = `MERKLE-DAG / ${view.total_leaves} LEAVES`;

    const { ctx, width, height } = fitCanvas();
    ctx.clearRect(0, 0, width, height);
    if (width < 4 || height < 4) return;

    const padX = 24;
    const padTop = 18;
    const padBottom = 16;
    const rows = Math.max(levels.length - 1, 1);
    const usable = Math.max(height - padTop - padBottom, 1);

    const nodes = levels.map((level, li) =>
      level.map((hash, index) => ({
        x: padX + ((width - padX * 2) * (index + 0.5)) / Math.max(level.length, 1),
        y: height - padBottom - (usable * li) / rows,
        hash,
      })),
    );

    const topLevel = levels.length - 1;
    const alphaFor = (li, reveal) => Math.min(1, Math.max(0, reveal - li));

    const draw = (reveal) => {
      ctx.clearRect(0, 0, width, height);

      // Edges first so nodes sit on top.
      for (let li = 0; li < topLevel; li += 1) {
        const children = nodes[li];
        const parents = nodes[li + 1];
        for (let pi = 0; pi < parents.length; pi += 1) {
          const alpha = Math.min(alphaFor(li, reveal), alphaFor(li + 1, reveal));
          if (alpha <= 0) continue;
          const parent = parents[pi];
          ctx.strokeStyle = `rgba(57, 228, 225, ${0.16 * alpha})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          for (const ci of [pi * 2, pi * 2 + 1]) {
            const child = children[ci];
            if (!child) continue;
            ctx.moveTo(parent.x, parent.y);
            ctx.lineTo(child.x, child.y);
          }
          ctx.stroke();
        }
      }

      // Nodes, root level highlighted last.
      for (let li = 0; li <= topLevel; li += 1) {
        const alpha = alphaFor(li, reveal);
        if (alpha <= 0) continue;
        const radius = li === 0 ? 1.6 : Math.min(1.4 + li * 0.7, 5);
        const isRoot = li === topLevel;
        for (const node of nodes[li]) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
          if (isRoot) {
            ctx.fillStyle = `rgba(138, 255, 177, ${alpha})`;
            ctx.shadowColor = `rgba(138, 255, 177, ${0.8 * alpha})`;
            ctx.shadowBlur = 16;
          } else {
            ctx.fillStyle = `rgba(57, 228, 225, ${0.85 * alpha})`;
            ctx.shadowColor = `rgba(57, 228, 225, ${0.5 * alpha})`;
            ctx.shadowBlur = li > topLevel - 3 ? 8 : 3;
          }
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }
    };

    const total = topLevel + 1.6;
    const duration = Math.min(700 + topLevel * 160, 2200);
    let start;
    const step = (timestamp) => {
      if (start === undefined) start = timestamp;
      const progress = Math.min((timestamp - start) / duration, 1);
      draw(progress * total);
      merkleAnimation = progress < 1 ? requestAnimationFrame(step) : 0;
    };
    merkleAnimation = requestAnimationFrame(step);
  }

  // ── Threat pins ──────────────────────────────────────────────────────────
  function clearThreatMarkers() {
    threatMarkers.innerHTML = "";
    clearThreatList();
  }

  function clearThreatList() {
    threatList.innerHTML = "";
    threatList.hidden = true;
  }

  /**
   * Pin every matched file around the vault radar. Position is deterministic
   * (golden-angle spread) so the same scan always lands the same pins. File
   * names are untrusted input, so every node is built through `textContent`.
   */
  function pinThreats(threats) {
    threatMarkers.innerHTML = "";
    const total = threats.length;
    threats.forEach((threat, index) => {
      const angle = index * 2.399963 + 0.6;
      const ring = 0.62 + (index % 3) * 0.13;
      const x = 50 + Math.cos(angle) * ring * 46;
      const y = 47 + Math.sin(angle) * ring * 40;

      const pin = document.createElement("span");
      pin.className = "threat-pin";
      pin.style.left = `${x}%`;
      pin.style.top = `${y}%`;
      pin.style.animationDelay = `${Math.min(index * 90, 900)}ms`;
      pin.title = `${threat.path}\n${threat.rules.map((rule) => rule.rule).join(", ")}`;

      const dot = document.createElement("span");
      dot.className = "pin-dot";
      const label = document.createElement("span");
      label.className = "pin-label";
      label.textContent = basename(threat.path);

      pin.append(dot, label);
      threatMarkers.append(pin);
    });
    if (total > 0) logLine(`  pinned ${total} threat location${total === 1 ? "" : "s"} on the radar`, "bad");
  }

  function renderThreats(threats) {
    threatList.innerHTML = "";
    threatList.hidden = false;
    for (const threat of threats) {
      const item = document.createElement("li");
      item.className = "threat-item";

      const head = document.createElement("div");
      head.className = "threat-head";
      const name = document.createElement("strong");
      name.textContent = basename(threat.path);
      name.title = threat.path;
      const size = document.createElement("span");
      size.textContent = formatBytes(threat.size);
      head.append(name, size);

      const path = document.createElement("div");
      path.className = "threat-path";
      path.textContent = threat.path;

      const rules = document.createElement("ul");
      rules.className = "threat-rules";
      for (const hit of threat.rules) {
        const rule = document.createElement("li");
        const id = document.createElement("code");
        id.textContent = hit.rule;
        rule.append(id);
        if (hit.description) {
          const desc = document.createElement("span");
          desc.textContent = hit.description;
          rule.append(desc);
        }
        rules.append(rule);
      }

      item.append(head, path, rules);
      threatList.append(item);
    }
  }

  // ── Credential rendering ─────────────────────────────────────────────────
  function renderCredential(report) {
    const signed = report.kind === "signed";
    credKind.textContent = signed ? "ED25519 SIGNED" : "LEDGER CREDENTIAL";
    credKind.className = `cred-kind ${signed ? "signed" : "unsigned"}`;
    credPath.textContent = report.output_path;
    credPath.title = report.output_path;
    credentialRow.hidden = false;
    clipboardHash = report.hash;
    copyLabel.textContent = signed ? "COPY PROVENANCE ROOT" : "COPY MERKLE ROOT";
    copyButton.hidden = false;
    summary.hidden = false;
    document.querySelector("#summary-hash").textContent = report.hash;
    document.querySelector("#summary-hash").title = report.hash;
  }

  // ── Clipboard ────────────────────────────────────────────────────────────
  async function copyToClipboard(text) {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      // Fallback for webviews that gate the async clipboard API.
      try {
        const scratch = document.createElement("textarea");
        scratch.value = text;
        scratch.setAttribute("readonly", "");
        scratch.style.position = "fixed";
        scratch.style.opacity = "0";
        document.body.append(scratch);
        scratch.select();
        const ok = document.execCommand("copy");
        scratch.remove();
        if (ok) return true;
      } catch (fallbackError) {
        logLine(`  clipboard unavailable: ${fallbackError}`, "bad");
      }
      logLine(`  clipboard unavailable: ${error}`, "bad");
      return false;
    }
  }

  // ── Engine bridge ────────────────────────────────────────────────────────
  async function invoke(command, args) {
    if (!hasCore) throw new Error("Native file access is only available in the Tauri desktop application.");
    return core.invoke(command, args);
  }

  async function refreshCapabilities() {
    try {
      const caps = await invoke("engine_capabilities");
      engineVersion.textContent = caps.version;
      scannerLinked = Boolean(caps.scanner_linked);
      scannerState.textContent = scannerLinked ? "YARA-X LINKED" : "NOT LINKED";
      scannerMetric.classList.toggle("unavailable", !scannerLinked);
      scannerNote.textContent = scannerLinked ? "PURE RUST / NO LIBCLANG" : "REBUILD WITH --features yara-scanner";
      threatLock.hidden = scannerLinked;
      footerCapability.textContent = scannerLinked
        ? "ENGINE LINKED · YARA-X LINKED · ED25519 SIGNER"
        : "ENGINE LINKED · SCANNER NOT ENABLED IN THIS BUILD";
      logLine(`engine ${caps.version} online · scanner ${scannerLinked ? "linked" : "absent"}`, "ok");
      if (!scannerLinked && mode === "threat") setMode("ledger");
    } catch (error) {
      scannerState.textContent = "UNAVAILABLE";
      scannerMetric.classList.add("unavailable");
      footerCapability.textContent = "ENGINE BRIDGE UNAVAILABLE";
      announce(`Could not probe the engine: ${error}`, "ERROR", "error");
      logLine(`engine probe failed: ${error}`, "bad");
    }
  }

  // ── Mode 01 — internal defense ───────────────────────────────────────────
  async function runLedger(path) {
    vault.classList.remove("merkle-active");
    clearCanvas();
    clearThreatMarkers();
    vault.classList.add("busy");
    setTerminalStatus("RUNNING", "run");
    setWorkspaceState("WEAVING LEDGER");
    stageState.textContent = "HASHING PROJECT";
    summary.hidden = true;
    credentialRow.hidden = true;
    copyButton.hidden = true;
    clipboardHash = "";

    logLine(`$ tw ledger --root "${path}"`, "cmd");
    announce(`Weaving a deterministic ledger for ${basename(path)}…`, "PROCESSING");

    const inventory = await invoke("inspect_project", { path });
    document.querySelector("#summary-files").textContent = inventory.file_count.toLocaleString();
    document.querySelector("#summary-size").textContent = formatBytes(inventory.total_bytes);
    document.querySelector("#summary-hash").textContent = inventory.merkle_root;
    document.querySelector("#summary-hash").title = inventory.merkle_root;
    summary.hidden = false;
    logLine(`  indexed ${inventory.file_count.toLocaleString()} files · ${formatBytes(inventory.total_bytes)}`, "ok");
    logLine(`  ledger root ${inventory.ledger_root_hash}`, "ok");

    stageState.textContent = "MINTING CREDENTIAL";
    setWorkspaceState("SIGNING CREDENTIAL");
    logLine("$ tw credential mint", "cmd");
    const credential = await invoke("generate_credential", { path });
    renderCredential(credential);
    if (credential.kind === "signed") {
      logLine(`  signed .twledger → ${credential.output_path}`, "ok");
      logLine(`  provenance root ${credential.hash}`, "ok");
      if (credential.signer_public_key) logLine(`  signer ${credential.signer_public_key}`, "dim");
    } else {
      logLine(`  ledger credential → ${credential.output_path}`, "warn");
      logLine(`  fallback reason: ${credential.reason}`, "dim");
      logLine(`  merkle root ${credential.hash}`, "ok");
    }

    const copied = await copyToClipboard(credential.hash);
    if (copied) {
      copyLabel.textContent = "COPIED";
      notify(credential.kind === "signed" ? "Provenance root copied to clipboard." : "Merkle root copied to clipboard.");
      logLine("  hash copied to clipboard", "ok");
      window.setTimeout(() => {
        copyLabel.textContent = credential.kind === "signed" ? "COPY PROVENANCE ROOT" : "COPY MERKLE ROOT";
      }, 2600);
    } else {
      copyLabel.textContent = "COPY HASH";
      notify("Clipboard was blocked — press the copy button.");
    }

    stageState.textContent = "RENDERING MERKLE-DAG";
    setWorkspaceState("RENDERING DAG");
    logLine("$ tw merkle render", "cmd");
    const view = await invoke("build_merkle", { path });
    logLine(`  ${view.total_leaves} leaves · ${view.levels.length} levels${view.truncated ? " (view capped)" : ""}`, "dim");
    drawMerkle(view);

    vault.classList.remove("busy");
    stageState.textContent = "LEDGER COMPLETE";
    setWorkspaceState("READY");
    setTerminalStatus("COMPLETE", "done");
    announce(
      `Ledger complete for ${inventory.path}. ${inventory.file_count.toLocaleString()} files indexed, ${credential.kind === "signed" ? "signed bundle" : "ledger credential"} minted.`,
      "COMPLETE",
      "success",
    );
  }

  // ── Mode 02 — threat hunting ─────────────────────────────────────────────
  async function runThreat(path) {
    clearCanvas();
    vault.classList.remove("merkle-active");
    clearThreatMarkers();
    if (!scannerLinked) {
      announce("The YARA-X scanner is not linked in this build. No verdict will be simulated.", "NOT LINKED", "error");
      return;
    }

    vault.classList.add("busy", "scanning");
    setTerminalStatus("SWEEPING", "run");
    setWorkspaceState("RADAR ACTIVE");
    stageState.textContent = "SWEEPING TARGET";
    stageFooterMid.textContent = "YARA-X / PURE RUST";
    summary.hidden = true;
    credentialRow.hidden = true;
    copyButton.hidden = true;

    logLine(`$ tw scan --target "${path}"`, "cmd");
    announce(`Radar sweep engaged on ${basename(path)}…`, "SCANNING");

    const report = await invoke("scan_target", { path, rules: null });
    logLine(`  rules: ${report.rules_path}`, "dim");
    logLine(`  ${report.total_files.toLocaleString()} files swept in ${report.duration_ms} ms`, "dim");

    vault.classList.remove("scanning");
    vault.classList.remove("busy");

    if (report.verdict === "SECURE") {
      vault.classList.add("secure");
      stageState.textContent = "SECURE PASSED";
      stageFooterMid.textContent = "NO SIGNATURE MATCH";
      setWorkspaceState("READY");
      setTerminalStatus("CLEAR", "done");
      logLine("  [SECURE PASSED] no signature match", "ok");
      announce(`${basename(report.target)} swept clean — ${report.total_files.toLocaleString()} files, no signature match.`, "SECURE PASSED", "success");
      return;
    }

    vault.classList.add("threat");
    stageState.textContent = "THREAT DETECTED";
    stageFooterMid.textContent = `${report.threat_count} HOSTILE SIGNATURE${report.threat_count === 1 ? "" : "S"}`;
    setWorkspaceState("ALERT");
    setTerminalStatus("HOSTILE", "bad");
    logLine(`  [THREAT DETECTED] ${report.threat_count} of ${report.total_files} files matched`, "bad");
    for (const threat of report.threats) {
      logLine(`    ! ${threat.path}`, "bad");
      for (const hit of threat.rules) {
        logLine(`      · ${hit.rule}${hit.description ? ` — ${hit.description}` : ""}`, "bad");
      }
    }
    renderThreats(report.threats);
    pinThreats(report.threats);
    announce(`${report.threat_count} hostile signature${report.threat_count === 1 ? "" : "s"} across ${report.total_files.toLocaleString()} files scanned.`, "THREAT DETECTED", "error");
  }

  // ── Drop routing ─────────────────────────────────────────────────────────
  async function handlePaths(paths) {
    if (!Array.isArray(paths) || paths.length === 0 || busy) return;
    const path = paths[0];
    if (paths.length > 1) notify("Only one target can be processed at a time; using the first.");
    if (!hasCore) {
      announce("Native file paths are only available inside the Tauri desktop application.", "DESKTOP ONLY", "error");
      return;
    }

    busy = true;
    clearConsole();
    clearThreatMarkers();
    vault.classList.remove("secure", "threat", "merkle-active", "scanning");
    try {
      if (mode === "threat") {
        await runThreat(path);
      } else {
        await runLedger(path);
      }
    } catch (error) {
      vault.classList.remove("busy", "scanning");
      stageState.textContent = "OPERATION FAILED";
      setWorkspaceState("FAILED");
      setTerminalStatus("FAILED", "bad");
      logLine(`  error: ${error}`, "bad");
      announce(`${mode === "threat" ? "Scan" : "Ledger"} failed: ${error}`, "ERROR", "error");
    } finally {
      busy = false;
      vault.classList.remove("busy", "scanning");
    }
  }

  // ── Mode switching ───────────────────────────────────────────────────────
  function setMode(nextMode) {
    mode = nextMode === "threat" && !scannerLinked ? "ledger" : nextMode;
    const threat = mode === "threat";

    tabs.forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    panel.setAttribute("aria-labelledby", threat ? "threat-tab" : "ledger-tab");
    vault.classList.toggle("threat-mode", threat);
    vault.classList.remove("secure", "threat", "merkle-active", "scanning");
    clearCanvas();
    clearThreatMarkers();
    credentialRow.hidden = true;
    summary.hidden = true;
    copyButton.hidden = true;
    clipboardHash = "";

    stageLabel.textContent = threat ? "EXTERNAL THREAT HUNT" : "INTERNAL LEDGER";
    stageState.textContent = threat ? "AWAITING TARGET" : "AWAITING INPUT";
    overlayLabel.textContent = threat ? "RELEASE TO SWEEP" : "RELEASE TO BEGIN";
    vaultOverline.innerHTML = threat ? "THE VAULT <span>·</span> THREAT HUNTING" : "THE VAULT <span>·</span> INTERNAL DEFENSE";
    vaultTitle.textContent = threat ? "Drop an artifact" : "Drop your project";
    vaultDescription.textContent = threat
      ? "Sweep a suspicious archive or executable through the pure-Rust YARA-X radar. Matched files are pinned with the exact rule that fired."
      : "Weave a deterministic ledger from your source tree and sign a provenance credential. Files are hashed locally; nothing is uploaded.";
    stageFooterMid.textContent = threat ? "YARA-X / PURE RUST" : "ROOT / MERKLE-STYLE LEDGER";
    setWorkspaceState("READY");
    setTerminalStatus("IDLE");
    announce(
      threat
        ? "Radar standing by. Drop a file or folder to begin a YARA-X sweep."
        : "Awaiting a project folder. The ledger will be generated by the local TrustWeave engine.",
      "STANDBY",
    );
  }

  // ── Wiring ───────────────────────────────────────────────────────────────
  tabs.forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));

  function showDragOverlay() {
    vault.classList.add("dragging");
    overlay.setAttribute("aria-hidden", "false");
  }

  function hideDragOverlay() {
    vault.classList.remove("dragging");
    overlay.setAttribute("aria-hidden", "true");
  }

  /**
   * Hover feedback only. With Tauri's native drag-drop handler active the
   * webview never receives HTML5 drag events, so the Tauri drag channel is the
   * primary source and the HTML5 listeners stay as a fallback.
   */
  function wireDragFeedback() {
    try {
      const webviewModule = tauri && tauri.webview;
      const current = webviewModule && typeof webviewModule.getCurrentWebview === "function"
        ? webviewModule.getCurrentWebview()
        : null;
      if (current && typeof current.onDragDropEvent === "function") {
        current.onDragDropEvent((event) => {
          const payload = (event && event.payload) || {};
          if (payload.type === "enter" || payload.type === "over") showDragOverlay();
          else hideDragOverlay();
        });
        return;
      }
    } catch (error) {
      logLine(`drag feedback channel unavailable: ${error}`, "dim");
    }

    document.addEventListener("dragenter", (event) => {
      if (!event.dataTransfer || ![...event.dataTransfer.types].includes("Files")) return;
      event.preventDefault();
      showDragOverlay();
    });
    document.addEventListener("dragover", (event) => {
      if (event.dataTransfer && [...event.dataTransfer.types].includes("Files")) event.preventDefault();
    });
    document.addEventListener("dragleave", (event) => {
      if (event.relatedTarget) return;
      hideDragOverlay();
    });
    document.addEventListener("drop", (event) => {
      if (!event.dataTransfer || ![...event.dataTransfer.types].includes("Files")) return;
      event.preventDefault();
      hideDragOverlay();
    });
  }

  function wireDropIntake() {
    if (events && typeof events.listen === "function") {
      events.listen("vault-drop", (event) => {
        hideDragOverlay();
        if (Array.isArray(event.payload) && event.payload.length > 0) handlePaths(event.payload);
      }).catch((error) => {
        announce(`Could not initialize native drop handling: ${error}`, "ERROR", "error");
      });
    } else {
      announce("Open this interface through the Tauri desktop app to process native drops.", "DESKTOP ONLY");
    }
  }

  wireDragFeedback();
  wireDropIntake();

  copyButton.addEventListener("click", async () => {
    if (!clipboardHash) return;
    const ok = await copyToClipboard(clipboardHash);
    if (ok) {
      copyLabel.textContent = "COPIED";
      notify("Hash copied to clipboard.");
      window.setTimeout(() => {
        copyLabel.textContent = credKind.textContent === "ED25519 SIGNED" ? "COPY PROVENANCE ROOT" : "COPY MERKLE ROOT";
      }, 2600);
    } else {
      notify("Clipboard was blocked by the webview.");
    }
  });

  let resizeTimer;
  window.addEventListener("resize", () => {
    if (!vault.classList.contains("merkle-active") || !lastMerkleView) return;
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      if (lastMerkleView) drawMerkle(lastMerkleView);
    }, 160);
  });

  document.querySelector("#about-button").addEventListener("click", () => aboutDialog.showModal());
  document.querySelector("#close-about").addEventListener("click", () => aboutDialog.close());
  aboutDialog.addEventListener("click", (event) => {
    if (event.target === aboutDialog) aboutDialog.close();
  });

  if (hasCore) {
    refreshCapabilities();
  } else {
    scannerState.textContent = "DESKTOP ONLY";
    scannerMetric.classList.add("unavailable");
    footerCapability.textContent = "OPEN INSIDE THE TAURI DESKTOP APP";
  }
  setMode("ledger");
})();
