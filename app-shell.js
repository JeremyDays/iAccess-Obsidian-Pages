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
  const encoder = new TextEncoder();

  let accessToken = null;

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

  function displayIdentity(idToken) {
    try {
      const part = idToken.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
      const payload = JSON.parse(decodeURIComponent(Array.from(atob(part), (char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
      userLabel.textContent = payload.email || payload.name || "Angemeldet";
    } catch {
      userLabel.textContent = "Angemeldet";
    }
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
    frameLogoutButton.addEventListener("click", logout);

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

  async function openSecureSite(tokens, returnPath) {
    setStatus("Zugriff wird geprüft und Inhalt entschlüsselt …");
    const [keyData, controller] = await Promise.all([
      fetchContentKey(tokens.access_token),
      serviceWorkerController()
    ]);
    await new Promise((resolve, reject) => {
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
        keyVersion: keyData.keyVersion
      }, [channel.port2]);
    });
    displayIdentity(tokens.id_token || "");
    secureFrame.src = appUrl(`secure-app/${returnPath}`);
    secureFrame.addEventListener("load", () => {
      loginDialog.hidden = true;
      document.querySelector(".lock-layer").hidden = true;
      document.querySelector("#public-preview").hidden = true;
      secureView.hidden = false;
    }, { once: true });
  }

  function logout() {
    accessToken = null;
    navigator.serviceWorker.controller?.postMessage({ type: "CLEAR_CONTENT_KEY" });
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
    const parameters = new URLSearchParams(location.search);
    if (parameters.has("error")) throw new Error(parameters.get("error_description") || "Die Anmeldung wurde abgebrochen.");
    if (parameters.has("code")) {
      setStatus("Anmeldung wird abgeschlossen …");
      const tokens = await exchangeCode(parameters.get("code"), parameters.get("state"));
      accessToken = tokens.access_token;
      history.replaceState({}, "", appUrl());
      await openSecureSite(tokens, tokens.returnPath);
    }
  }

  loginButton.addEventListener("click", () => startLogin().catch((error) => {
    loginButton.disabled = false;
    setStatus(error.message, true);
  }));
  logoutButton.addEventListener("click", logout);
  secureFrame.addEventListener("load", dockSessionToolbar);
  window.addEventListener("pagehide", () => {
    accessToken = null;
    navigator.serviceWorker.controller?.postMessage({ type: "CLEAR_CONTENT_KEY" });
  });
  initialize().catch((error) => {
    loginButton.disabled = false;
    history.replaceState({}, "", appUrl());
    setStatus(error.message, true);
  });
})();
