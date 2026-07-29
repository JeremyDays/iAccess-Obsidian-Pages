(() => {
  "use strict";

  const config = globalThis.IACCESS_AUTH_CONFIG;
  const loginButton = document.querySelector("#login-button");
  const logoutButton = document.querySelector("#logout-button");
  const status = document.querySelector("#status");
  const loginDialog = document.querySelector("#login-dialog");
  const secureView = document.querySelector("#secure-view");
  const secureFrame = document.querySelector("#secure-frame");
  const userLabel = document.querySelector("#user-label");
  const lockLayer = document.querySelector(".lock-layer");
  const publicPreview = document.querySelector("#public-preview");
  const encoder = new TextEncoder();

  const DAILY_SESSION_MS = 24 * 60 * 60 * 1000;
  const DAILY_SESSION_STORAGE_KEY = "iaccess.daily-session.v1";
  const SESSION_DATABASE = "iaccess-secure-session";
  const SESSION_STORE = "keys";
  const SESSION_WRAP_KEY_ID = "daily-session";
  const SESSION_AAD = encoder.encode("iaccess-odo-daily-session:v1");

  let activeKeyData = null;
  let activeSessionExpiresAt = 0;

  function appUrl(relative = "") {
    const base = config.basePath || "";
    return `${base}/${relative}`.replace(/\/$/, relative ? "" : "/");
  }

  function callbackUrl() {
    return `${config.siteOrigin}${appUrl()}`;
  }

  function setStatus(message, isError = false) {
    status.textContent = message;
    status.classList.toggle("error", isError);
  }

  function randomBase64Url(length = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    return base64Url(bytes);
  }

  function base64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function bytesFromBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function sha256Base64Url(value) {
    return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
  }

  function authBase() {
    return `https://${config.auth0Domain}`;
  }

  function requestedDocument() {
    let pathname = decodeURIComponent(location.pathname).replace(/^\/+/, "");
    const base = (config.basePath || "").replace(/^\/+/, "");
    if (base && (pathname === base || pathname.startsWith(`${base}/`))) pathname = pathname.slice(base.length).replace(/^\/+/, "");
    if (!pathname || pathname === "index.html" || pathname === "404.html") return config.defaultDocument;
    if (pathname.startsWith("secure-app/")) pathname = pathname.slice("secure-app/".length);
    if (pathname.includes("..")) return config.defaultDocument;
    return pathname;
  }

  async function startLogin() {
    loginButton.disabled = true;
    setStatus("Sichere Anmeldung wird geöffnet …");
    const verifier = randomBase64Url(48);
    const state = randomBase64Url(24);
    const returnPath = requestedDocument();
    sessionStorage.setItem("iaccess.oauth", JSON.stringify({ verifier, state, returnPath, createdAt: Date.now() }));
    const parameters = new URLSearchParams({
      response_type: "code",
      client_id: config.auth0ClientId,
      redirect_uri: callbackUrl(),
      audience: config.auth0Audience,
      scope: "openid profile email",
      state,
      code_challenge: await sha256Base64Url(verifier),
      code_challenge_method: "S256"
    });
    location.assign(`${authBase()}/authorize?${parameters}`);
  }

  async function exchangeCode(code, state) {
    const savedRaw = sessionStorage.getItem("iaccess.oauth");
    sessionStorage.removeItem("iaccess.oauth");
    if (!savedRaw) throw new Error("Anmeldestatus fehlt. Bitte erneut anmelden.");
    const saved = JSON.parse(savedRaw);
    if (saved.state !== state || Date.now() - saved.createdAt > 10 * 60 * 1000) throw new Error("Anmeldestatus ist ungültig oder abgelaufen.");
    const response = await fetch(`${authBase()}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: config.auth0ClientId,
        code,
        code_verifier: saved.verifier,
        redirect_uri: callbackUrl()
      }),
      cache: "no-store",
      credentials: "omit"
    });
    if (!response.ok) throw new Error("Die Anmeldung konnte nicht abgeschlossen werden.");
    const tokens = await response.json();
    if (!tokens.access_token) throw new Error("Auth0 hat kein Zugriffstoken geliefert.");
    return { ...tokens, returnPath: saved.returnPath || config.defaultDocument };
  }

  function identityFromIdToken(idToken) {
    try {
      const part = idToken.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
      const payload = JSON.parse(decodeURIComponent(Array.from(atob(part), (char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
      return payload.email || payload.name || "Angemeldet";
    } catch {
      return "Angemeldet";
    }
  }

  function openSessionDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(SESSION_DATABASE, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(SESSION_STORE)) request.result.createObjectStore(SESSION_STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Der geschützte Sitzungsspeicher konnte nicht geöffnet werden."));
    });
  }

  async function sessionStoreRequest(mode, action) {
    const database = await openSessionDatabase();
    try {
      return await new Promise((resolve, reject) => {
        const transaction = database.transaction(SESSION_STORE, mode);
        const request = action(transaction.objectStore(SESSION_STORE));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("Der geschützte Sitzungsspeicher konnte nicht gelesen werden."));
      });
    } finally {
      database.close();
    }
  }

  async function wrappingKey(create = false) {
    let key = await sessionStoreRequest("readonly", (store) => store.get(SESSION_WRAP_KEY_ID));
    if (!key && create) {
      key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      await sessionStoreRequest("readwrite", (store) => store.put(key, SESSION_WRAP_KEY_ID));
    }
    return key || null;
  }

  async function clearDailySession() {
    try {
      localStorage.removeItem(DAILY_SESSION_STORAGE_KEY);
    } catch {
      // Browser may disable persistent storage in a private context.
    }
    try {
      await sessionStoreRequest("readwrite", (store) => store.delete(SESSION_WRAP_KEY_ID));
    } catch {
      // A failed cleanup must not prevent an explicit logout.
    }
  }

  async function saveDailySession(keyData, identity, expiresAt) {
    const key = await wrappingKey(true);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = encoder.encode(JSON.stringify({
      keyBase64: keyData.keyBase64,
      keyVersion: keyData.keyVersion,
      identity,
      expiresAt
    }));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: SESSION_AAD }, key, plain);
    localStorage.setItem(DAILY_SESSION_STORAGE_KEY, JSON.stringify({
      version: 1,
      expiresAt,
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(encrypted))
    }));
  }

  async function restoreDailySession() {
    try {
      const stored = localStorage.getItem(DAILY_SESSION_STORAGE_KEY);
      if (!stored) return null;
      const record = JSON.parse(stored);
      if (record.version !== 1 || !Number.isFinite(record.expiresAt) || record.expiresAt <= Date.now()) throw new Error("Tagessitzung abgelaufen");
      const key = await wrappingKey(false);
      if (!key) throw new Error("Sitzungsschlüssel fehlt");
      const plain = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: bytesFromBase64(record.iv),
        additionalData: SESSION_AAD
      }, key, bytesFromBase64(record.ciphertext));
      const session = JSON.parse(new TextDecoder().decode(plain));
      const rawKey = bytesFromBase64(session.keyBase64);
      if (
        rawKey.byteLength !== 32
        || typeof session.keyVersion !== "string"
        || !session.keyVersion
        || session.expiresAt !== record.expiresAt
      ) throw new Error("Tagessitzung ist ungültig");
      return {
        keyData: { keyBase64: session.keyBase64, keyVersion: session.keyVersion },
        identity: session.identity || "Angemeldet",
        expiresAt: session.expiresAt
      };
    } catch {
      await clearDailySession();
      return null;
    }
  }

  function activeSessionIsValid() {
    return Boolean(activeKeyData && activeSessionExpiresAt > Date.now());
  }

  function dockSessionToolbar() {
    const frameDocument = secureFrame.contentDocument;
    if (!frameDocument) return;

    const navigation = frameDocument.querySelector(".top-nav");
    if (!navigation || navigation.querySelector(".iaccess-session-nav")) return;

    if (!frameDocument.querySelector('link[data-iaccess-session-style]')) {
      const stylesheet = frameDocument.createElement("link");
      stylesheet.rel = "stylesheet";
      stylesheet.href = appUrl("session-toolbar.css");
      stylesheet.dataset.iaccessSessionStyle = "";
      frameDocument.head.append(stylesheet);
    }

    const sessionNavigation = frameDocument.createElement("div");
    sessionNavigation.className = "iaccess-session-nav";
    sessionNavigation.setAttribute("aria-label", "Benutzersitzung");

    const identity = frameDocument.createElement("span");
    identity.className = "iaccess-session-user";
    identity.textContent = userLabel.textContent || "Angemeldet";

    const frameLogoutButton = frameDocument.createElement("button");
    frameLogoutButton.className = "iaccess-session-logout";
    frameLogoutButton.type = "button";
    frameLogoutButton.textContent = "Abmelden";
    frameLogoutButton.addEventListener("click", () => logout().catch((error) => setStatus(error.message, true)));

    sessionNavigation.append(identity, frameLogoutButton);
    navigation.append(sessionNavigation);
  }

  async function fetchContentKey(token) {
    const response = await fetch(config.keyEndpoint, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      cache: "no-store",
      credentials: "omit"
    });
    if (response.status === 401 || response.status === 403) throw new Error("Dieses Konto ist nicht für die Datenbank freigeschaltet.");
    if (!response.ok) throw new Error("Der geschützte Inhalt ist derzeit nicht erreichbar.");
    const data = await response.json();
    if (!data.keyBase64 || !data.keyVersion) throw new Error("Der Schlüsseldienst hat eine ungültige Antwort geliefert.");
    return data;
  }

  async function serviceWorkerController() {
    const registration = await navigator.serviceWorker.register(appUrl("service-worker.js"), { scope: appUrl() });
    await navigator.serviceWorker.ready;
    if (navigator.serviceWorker.controller) return navigator.serviceWorker.controller;
    return await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("Der geschützte Browser-Speicher konnte nicht gestartet werden.")), 8000);
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        clearTimeout(timeout);
        resolve(navigator.serviceWorker.controller || registration.active);
      }, { once: true });
      registration.active?.postMessage({ type: "CLAIM_CLIENTS" });
    });
  }

  async function provideKeyToWorker(controller, keyData, expiresAt, requestId = null) {
    return await new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timeout = setTimeout(() => reject(new Error("Der Entschlüsselungsschlüssel konnte nicht sicher übergeben werden.")), 8000);
      channel.port1.onmessage = (event) => {
        clearTimeout(timeout);
        if (event.data?.ok) resolve();
        else reject(new Error("Der Entschlüsselungsschlüssel wurde vom Browser abgelehnt."));
      };
      controller.postMessage({
        type: "SET_CONTENT_KEY",
        keyBase64: keyData.keyBase64,
        keyVersion: keyData.keyVersion,
        expiresAt,
        requestId
      }, [channel.port2]);
    });
  }

  async function openSecureSite(session, returnPath) {
    setStatus("Zugriff wird geprüft und Inhalt entschlüsselt …");
    activeKeyData = session.keyData;
    activeSessionExpiresAt = session.expiresAt;
    userLabel.textContent = session.identity || "Angemeldet";
    const controller = await serviceWorkerController();
    await provideKeyToWorker(controller, session.keyData, session.expiresAt);
    secureFrame.src = appUrl(`secure-app/${returnPath}`);
    secureFrame.addEventListener("load", () => {
      loginDialog.hidden = true;
      lockLayer.hidden = true;
      publicPreview.hidden = true;
      secureView.hidden = false;
    }, { once: true });
  }

  async function expireSession(message = "Ihre Tagessitzung ist abgelaufen. Bitte melden Sie sich erneut an.") {
    activeKeyData = null;
    activeSessionExpiresAt = 0;
    navigator.serviceWorker.controller?.postMessage({ type: "CLEAR_CONTENT_KEY" });
    await clearDailySession();
    secureFrame.src = "about:blank";
    secureView.hidden = true;
    publicPreview.hidden = false;
    lockLayer.hidden = false;
    loginDialog.hidden = false;
    loginButton.disabled = false;
    setStatus(message, true);
  }

  async function handleServiceWorkerMessage(event) {
    const data = event.data || {};
    if (data.type === "CONTENT_KEY_REQUIRED") {
      if (activeSessionIsValid()) {
        await provideKeyToWorker(event.source, activeKeyData, activeSessionExpiresAt, data.requestId);
      } else {
        event.source?.postMessage({ type: "CONTENT_KEY_UNAVAILABLE", requestId: data.requestId });
        await expireSession();
      }
    }
    if (data.type === "SESSION_EXPIRED") await expireSession();
  }

  async function logout() {
    await expireSession("Sie wurden abgemeldet.");
    const parameters = new URLSearchParams({ client_id: config.auth0ClientId, returnTo: callbackUrl() });
    location.assign(`${authBase()}/v2/logout?${parameters}`);
  }

  async function initialize() {
    if (window.top !== window.self) {
      loginButton.disabled = true;
      setStatus("Bitte öffnen Sie die Datenbank direkt in einem eigenen Browserfenster.", true);
      return;
    }
    if (!config || !config.auth0Domain || !config.keyEndpoint) {
      loginButton.disabled = true;
      setStatus("Die Anmeldung ist noch nicht fertig konfiguriert.", true);
      return;
    }
    if (!("serviceWorker" in navigator) || !crypto?.subtle) {
      loginButton.disabled = true;
      setStatus("Dieser Browser unterstützt die erforderliche sichere Entschlüsselung nicht.", true);
      return;
    }
    navigator.serviceWorker.addEventListener("message", (event) => {
      handleServiceWorkerMessage(event).catch(() => expireSession());
    });
    const parameters = new URLSearchParams(location.search);
    if (parameters.has("error")) throw new Error(parameters.get("error_description") || "Die Anmeldung wurde abgebrochen.");
    if (parameters.has("code")) {
      setStatus("Anmeldung wird abgeschlossen …");
      const tokens = await exchangeCode(parameters.get("code"), parameters.get("state"));
      const keyData = await fetchContentKey(tokens.access_token);
      const session = {
        keyData,
        identity: identityFromIdToken(tokens.id_token || ""),
        expiresAt: Date.now() + DAILY_SESSION_MS
      };
      try {
        await saveDailySession(session.keyData, session.identity, session.expiresAt);
      } catch {
        // The active in-memory session remains usable even if this browser blocks persistent storage.
      }
      history.replaceState({}, "", appUrl());
      await openSecureSite(session, tokens.returnPath);
      return;
    }
    const restored = await restoreDailySession();
    if (restored) await openSecureSite(restored, requestedDocument());
  }

  loginButton.addEventListener("click", () => startLogin().catch((error) => {
    loginButton.disabled = false;
    setStatus(error.message, true);
  }));
  logoutButton.addEventListener("click", () => logout().catch((error) => setStatus(error.message, true)));
  secureFrame.addEventListener("load", dockSessionToolbar);
  initialize().catch((error) => {
    loginButton.disabled = false;
    history.replaceState({}, "", appUrl());
    setStatus(error.message, true);
  });
})();
