"use strict";

// The client holds only the CSRF nonce. Authentication stays in the host-only
// HttpOnly cookie. It never stores pairing codes or resumes input on reconnect.
class SessionClient {
  #fetch; #crypto; #now; #changed; #csrf = null; #busy = false; #stopBusy = false;
  #polling = false; #pending = null; #fenced = false; #received = 0; #frameAge = Infinity;
  #generation = 0; #sequenceGeneration = -1; #sequence = -1; #backend = null; #documentGeneration = -1;

  constructor(fetcher, cryptoProvider, now, changed = () => {}) {
    this.#fetch = fetcher; this.#crypto = cryptoProvider; this.#now = now; this.#changed = changed;
    this.session = null; this.view = null; this.message = "Unpaired"; this.operation = null; this.operations = [];
  }

  async #request(path, body = null, maximum = 2097152) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const headers = body === null ? {} : {"Content-Type": "application/json"};
      if (body !== null && path !== "/pair") {
        if (!this.#csrf) throw new Error("Session authorization unavailable");
        headers["X-CSRF-Token"] = this.#csrf;
      }
      const response = await this.#fetch(path, {method: body === null ? "GET" : "POST", headers,
        body: body === null ? undefined : JSON.stringify(body), credentials: "same-origin",
        cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", signal: controller.signal});
      const reader = response.body.getReader();
      const parts = []; let size = 0;
      try {
        for (;;) {
          const next = await reader.read();
          if (next.done) break;
          size += next.value.byteLength;
          if (size > maximum) { await reader.cancel(); throw new Error("Response exceeds its declared bound"); }
          parts.push(next.value);
        }
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(size); let at = 0;
      for (const part of parts) { bytes.set(part, at); at += part.byteLength; }
      if (!response.ok) {
        const error = new Error("Request refused or its outcome is unavailable"); error.status = response.status; throw error;
      }
      return {bytes, sha256: response.headers.get("x-content-sha256")};
    } finally { clearTimeout(timer); }
  }

  async #json(path, body = null) {
    return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode((await this.#request(path, body)).bytes));
  }

  #emit() { this.#changed(this); }

  async pair(code) {
    // The caller clears the form before this request. A lost reply never causes
    // the same single-use code to be automatically redeemed again.
    this.#csrf = null;
    try { await this.#json("/pair", {code}); await this.refresh(); }
    catch (_) { this.message = "Pairing was not confirmed. Ask the host for a new code if the original was consumed."; this.#emit(); }
  }

  async refresh() {
    try {
      const reply = await this.#json("/session");
      this.#csrf = reply.csrf_token;
      const {csrf_token, ...visible} = reply;
      this.session = visible;
      this.message = "Original session rights observed. No rights or work were renewed.";
    } catch (_) {
      this.#csrf = null; this.session = null; this.view = null;
      this.message = "No valid viewer session. Pair with a code issued by your host.";
    }
    this.#emit();
  }

  async poll() {
    if (this.#polling || !this.session?.rights?.observe?.available) return;
    const started = this.#now();
    this.#polling = true; this.#emit();
    try {
      const view = await this.#json("/observation");
      if (view.session_id !== this.session.session_id || view.target_id !== this.session.target_id || view.context_id !== this.session.context_id) {
        throw new Error("Original session identity changed");
      }
      if (!Number.isSafeInteger(view.control_generation) || !Number.isSafeInteger(view.document_generation)
          || view.control_generation < 0 || view.document_generation < 0) throw new Error("Invalid observation generation");
      if (this.#backend !== null && this.#backend !== view.backend_epoch) throw new Error("Original backend identity changed");
      if (view.control_generation < this.#generation || view.document_generation < this.#documentGeneration) return;
      if (view.frame) {
        for (const field of ["session_id", "context_id", "target_id", "backend_epoch", "control_generation", "document_id"]) {
          if (view.frame[field] !== view[field]) throw new Error("Frame identity changed");
        }
        if (!Number.isSafeInteger(view.frame.sequence) || view.frame.sequence < 0) throw new Error("Invalid frame sequence");
        if (view.control_generation === this.#sequenceGeneration && view.frame.sequence < this.#sequence) return;
        const raw = Uint8Array.from(atob(view.frame.jpeg_base64), value => value.charCodeAt(0));
        const actual = await this.#hash(raw);
        if (actual !== view.frame.jpeg_sha256) throw new Error("Frame checksum changed");
      }
      // A mutation acknowledgement may have advanced the floor while hashing.
      if (view.control_generation < this.#generation) return;
      const received = this.#now(), age = view.frame ? view.server_time_ms - view.frame.captured_at_ms : Infinity;
      this.view = view; this.#received = received; this.#backend = view.backend_epoch;
      this.#generation = Math.max(this.#generation, view.control_generation);
      this.#documentGeneration = Math.max(this.#documentGeneration, view.document_generation);
      if (view.frame) { this.#sequenceGeneration = view.control_generation; this.#sequence = view.frame.sequence; }
      // Conservatively include all transit, body reading and hashing time.
      // A backwards monotonic clock cannot make the observation fresh again.
      this.#frameAge = Number.isFinite(age) && age >= 0 && received >= started ? age + received - started : Infinity;
      this.message = view.frame ? "Latest observation from the original target." : "No fresh live observation is available.";
    } catch (error) {
      this.view = null; this.#frameAge = Infinity;
      if ([403, 429].includes(error.status) && this.session?.rights?.observe) this.session.rights.observe.available = false;
      this.message = "Observation unavailable. Work and ownership were not restarted.";
    } finally { this.#polling = false; this.#emit(); }
  }

  frameAge() { const now = this.#now(); return now >= this.#received ? this.#frameAge + now - this.#received : Infinity; }
  fresh() { return Boolean(this.view?.frame) && this.frameAge() <= this.view.frame_max_age_ms; }
  canInput() {
    return Boolean(this.session?.rights?.control?.available && this.view?.mode === "human"
      && this.view.actor_id === this.session.actor_id && this.fresh() && !this.#polling && !this.#busy && !this.#pending && !this.#fenced);
  }
  canTakeover() { return Boolean(this.session?.rights?.control?.available && this.view
    && !["human", "stopping", "stopped", "lost", "quiescing"].includes(this.view.mode) && !this.#busy && !this.#pending && !this.#fenced); }
  canStop() { return Boolean(this.session?.rights?.stop?.available && !this.#stopBusy && !this.#pending?.stop
    && !(this.operation?.kind === "stop" && this.operation.state === "confirmed")); }

  #acceptAcknowledgement(reply, operation_id) {
    if (reply.operation_id !== operation_id || !Number.isSafeInteger(reply.control_generation) || reply.control_generation < 0
        || !["action", "takeover", "handback", "stop"].includes(reply.kind)
        || !["queued", "dispatched", "applied", "not_applied", "unknown", "confirmed", "pending", "failed"].includes(reply.state)) {
      throw new Error("Invalid original operation acknowledgement");
    }
    this.#generation = Math.max(this.#generation, reply.control_generation);
    if (this.view && this.view.control_generation < this.#generation) this.view = null;
  }

  async #mutate(path, fields) {
    const stop = path === "/stop";
    if (stop ? !this.canStop() : this.#busy || this.#pending || this.#fenced) return null;
    if (stop) { this.#stopBusy = true; this.#fenced = true; }
    else this.#busy = true;
    const operation_id = this.#crypto.randomUUID();
    const pending = {operation_id, stop, polls: 0}; this.#pending = pending;
    const kind = path === "/actions" ? "action" : path.slice(1);
    let result = {operation_id, state: "requesting", kind};
    this.operation = result; this.operations.push(result); this.operations = this.operations.slice(-32);
    this.#emit();
    try {
      const reply = await this.#json(path, {...fields, operation_id});
      this.#acceptAcknowledgement(reply, operation_id);
      result = reply;
      if (this.#pending === pending) {
        this.operation = reply;
        if (["applied", "not_applied", "confirmed", "failed"].includes(reply.state)) this.#pending = null;
      }
    } catch (_) {
      result = {operation_id, state: "unknown", kind};
      if (this.#pending === pending) this.operation = result;
      this.message = "The operation outcome is unknown. It will not be resubmitted.";
    } finally {
      this.operations = this.operations.map(item => item.operation_id === operation_id ? result : item);
      if (stop) this.#stopBusy = false; else this.#busy = false;
      this.#emit();
    }
    return result;
  }

  async input(action, parameters) {
    if (!this.canInput()) return null;
    const view = this.view;
    return this.#mutate("/actions", {session_id: view.session_id, context_id: view.context_id, target_id: view.target_id,
      control_generation: view.control_generation, document_id: view.document_id, document_generation: view.document_generation,
      observation_id: view.frame.observation_id, action, parameters});
  }
  async takeover() {
    if (!this.canTakeover()) return null;
    return this.#mutate("/takeover", {control_generation: this.view.control_generation});
  }
  async handback() {
    if (!this.canInput()) return null;
    return this.#mutate("/handback", {control_generation: this.view.control_generation, observation_id: this.view.frame.observation_id});
  }
  async stop() { return this.#mutate("/stop", {}); }

  async checkOperation() {
    const pending = this.#pending;
    if (!pending || pending.polls >= 20 || this.#busy || this.#stopBusy) return;
    pending.polls += 1;
    try {
      const reply = await this.#json((pending.stop ? "/stop-operations/" : "/operations/") + pending.operation_id);
      if (this.#pending !== pending || reply.operation_id !== pending.operation_id) return;
      this.#acceptAcknowledgement(reply, pending.operation_id);
      this.operation = reply;
      this.operations = this.operations.map(item => item.operation_id === reply.operation_id ? reply : item);
      if (["applied", "not_applied", "confirmed", "failed"].includes(reply.state)) this.#pending = null;
    } catch (_) { this.message = "Original operation status unavailable. No action was repeated."; }
    this.#emit();
  }

  async #hash(bytes) {
    return Array.from(new Uint8Array(await this.#crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
  }
  async readResult(name, expected) {
    if (!["result.json", "events.json", "screenshot.jpg"].includes(name)) throw new Error("Unknown retained result");
    const reply = await this.#request("/results/" + name, null, 16777216);
    const actual = await this.#hash(reply.bytes);
    if (actual !== reply.sha256 || actual !== expected) throw new Error("Retained bytes failed their checksum");
    return reply.bytes;
  }
}

function mountSessionClient(document, fetcher, cryptoProvider, now) {
  const get = id => document.getElementById(id);
  const text = (id, value) => { if (get(id).textContent !== value) get(id).textContent = value; };
  let frameURL = null, resultURL = null, shownFrame = null, shownResults = null, shownCorrections = null, running = false;
  const client = new SessionClient(fetcher, cryptoProvider, now, render);
  function render() {
    const view = client.view, session = client.session;
    text("message", client.message);
    get("pair-panel").hidden = Boolean(session);
    get("session-target").textContent = session ? session.session_id + " / " + session.target_id : "Unpaired";
    get("owner").textContent = view ? (view.actor_id || "None confirmed") + " · " + view.mode : "Unknown";
    get("generations").textContent = view ? view.control_generation + " / " + view.document_generation : "Unknown";
    get("rights").textContent = session ? Object.entries(session.rights).map(([right, value]) =>
      right + (value.available ? " until " + new Date(value.expires_at_ms).toISOString() : " unavailable")).join("; ") : "None observed";
    get("takeover").disabled = !client.canTakeover();
    get("handback").disabled = !client.canInput();
    get("stop").disabled = !client.canStop();
    get("input-controls").disabled = !client.canInput();
    get("frame").classList.toggle("controllable", client.canInput());
    const fresh = client.fresh();
    get("freshness").textContent = view?.frame ? (fresh ? "Live" : "Stale") + " · " + Math.round(client.frameAge()) + " ms old" : "No fresh frame";
    get("frame-label").textContent = fresh ? "Live observation" : "No live frame";
    get("frame-label").classList.toggle("live", fresh);
    get("frame").hidden = !view?.frame;
    if (view?.frame && shownFrame !== view.frame.observation_id) {
      if (frameURL) URL.revokeObjectURL(frameURL);
      const bytes = Uint8Array.from(atob(view.frame.jpeg_base64), value => value.charCodeAt(0));
      frameURL = URL.createObjectURL(new Blob([bytes], {type: "image/jpeg"}));
      get("frame").src = frameURL; shownFrame = view.frame.observation_id;
    }
    get("projection").textContent = view?.frame ? JSON.stringify(view.frame.projection, null, 2) : "No current page values.";
    const corrections = JSON.stringify(view?.corrections || []);
    if (shownCorrections !== corrections) {
      shownCorrections = corrections; get("corrections").replaceChildren();
      for (const item of view?.corrections || []) {
        const line = document.createElement("li"); line.textContent = item.actor_id + ": " + item.text; get("corrections").append(line);
      }
    }
    if (client.operation) text("operation", client.operations.map(item =>
      item.kind + " · " + item.state + " · original " + item.operation_id).join("\n"));
    const results = JSON.stringify(view?.results || []);
    if (shownResults === results) return;
    shownResults = results; get("results").replaceChildren();
    for (const item of view?.results || []) {
      const button = document.createElement("button"); button.type = "button"; button.textContent = "Open " + item.name;
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          const bytes = await client.readResult(item.name, item.sha256);
          if (item.name === "screenshot.jpg") {
            if (resultURL) URL.revokeObjectURL(resultURL);
            resultURL = URL.createObjectURL(new Blob([bytes], {type: "image/jpeg"}));
            get("result-image").src = resultURL; get("result-image").hidden = false;
          } else { get("result-text").textContent = new TextDecoder("utf-8", {fatal: true}).decode(bytes); }
        } catch (_) { get("result-text").textContent = "Original result unavailable or checksum not confirmed."; }
        finally { button.disabled = false; }
      });
      get("results").append(button);
    }
  }
  get("pair-form").addEventListener("submit", async event => {
    event.preventDefault(); const code = get("pair-code").value; get("pair-code").value = ""; await client.pair(code);
  });
  get("reconnect").addEventListener("click", () => client.refresh());
  get("takeover").addEventListener("click", () => client.takeover());
  get("handback").addEventListener("click", () => client.handback());
  get("stop").addEventListener("click", () => client.stop());
  get("frame").addEventListener("click", event => {
    if (!client.canInput()) return;
    const rectangle = get("frame").getBoundingClientRect(), frame = client.view.frame;
    const x = Math.floor((event.clientX - rectangle.left) * frame.width / rectangle.width);
    const y = Math.floor((event.clientY - rectangle.top) * frame.height / rectangle.height);
    if (x >= 0 && y >= 0 && x < frame.width && y < frame.height) client.input("click", {x, y, button: "left"});
  });
  get("navigate-form").addEventListener("submit", event => { event.preventDefault(); client.input("navigate", {url: get("navigate-url").value}); });
  get("type-form").addEventListener("submit", event => { event.preventDefault(); const text = get("type-text").value; get("type-text").value = ""; client.input("type", {text}); });
  get("key-form").addEventListener("submit", event => { event.preventDefault(); client.input("key", {key: get("key-name").value}); });
  get("correction-form").addEventListener("submit", event => {
    event.preventDefault(); const text = get("correction-text").value;
    if (new TextEncoder().encode(text).length <= 2048) client.input("correction", {text});
  });
  async function tick() {
    if (running) return;
    running = true;
    try { if (!document.hidden) { await client.poll(); await client.checkOperation(); } render(); }
    finally { running = false; setTimeout(tick, 500); }
  }
  // Frame age keeps advancing while a slow fetch is outstanding. This timer
  // only updates the view; it never polls, renews rights or resumes dispatch.
  setInterval(render, 200);
  client.refresh().then(tick);
  return client;
}

if (typeof module !== "undefined" && module.exports) module.exports = {SessionClient, mountSessionClient};
else mountSessionClient(document, fetch.bind(globalThis), crypto, () => performance.now());
