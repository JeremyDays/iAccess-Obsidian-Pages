"use strict";

const FORMAT_VERSION = 2;
const SCOPE_PATH = new URL(self.registration.scope).pathname.replace(/\/$/, "");
const SECURE_PREFIX = `${SCOPE_PATH}/secure-app/`;
const encoder = new TextEncoder();
const MAX_SESSION_MS = 24 * 60 * 60 * 1000;
const SESSION_DATABASE = "iaccess-secure-session";
const SESSION_STORE = "keys";
const SESSION_WRAP_KEY_ID = "daily-session";
const SESSION_RECORD_ID = "daily-session-record";
const SESSION_AAD = encoder.encode("iaccess-odo-daily-session:v1");
let contentKey = null;
let keyVersion = null;
let keyExpiresAt = 0;
let manifestPromise = null;
let recoveryPromise = null;
let recoveryRequestId = 0;
let recoveryResolver = null;

function appUrl(relative) {
  return `${SCOPE_PATH}/${relative}`;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.type === "CLAIM_CLIENTS") event.waitUntil(self.clients.claim());
  if (data.type === "CLEAR_CONTENT_KEY") {
    clearContentKey();
    finishRecovery(data.requestId, false);
    event.waitUntil(clearPersistedSession());
  }
  if (data.type === "CONTENT_KEY_UNAVAILABLE") {
    finishRecovery(data.requestId, false);
  }
  if (data.type === "SET_CONTENT_KEY") {
    event.waitUntil((async () => {
      try {
        const raw = fromBase64(data.keyBase64);
        if (raw.byteLength !== 32) throw new Error("Ungueltiger Inhaltsschluessel");
        if (
          !Number.isFinite(data.expiresAt)
          || data.expiresAt <= Date.now()
          || data.expiresAt > Date.now() + MAX_SESSION_MS + 60_000
        ) throw new Error("Ungueltige Tagessitzung");
        contentKey = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
        keyVersion = data.keyVersion;
        keyExpiresAt = data.expiresAt;
        manifestPromise = null;
        finishRecovery(data.requestId, true);
        event.ports[0]?.postMessage({ ok: true });
      } catch (error) {
        clearContentKey();
        finishRecovery(data.requestId, false);
        event.ports[0]?.postMessage({ ok: false });
        throw error;
      }
    })());
  }
});

function clearContentKey() {
  contentKey = null;
  keyVersion = null;
  keyExpiresAt = 0;
  manifestPromise = null;
}

function contentKeyIsValid() {
  return Boolean(contentKey && keyVersion && keyExpiresAt > Date.now());
}

function openSessionDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(SESSION_DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(SESSION_STORE)) request.result.createObjectStore(SESSION_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Sitzungsspeicher nicht erreichbar"));
  });
}

async function sessionStoreRequest(mode, action) {
  const database = await openSessionDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(SESSION_STORE, mode);
      const request = action(transaction.objectStore(SESSION_STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Sitzungsspeicher konnte nicht gelesen werden"));
    });
  } finally {
    database.close();
  }
}

async function clearPersistedSession() {
  try {
    await sessionStoreRequest("readwrite", (store) => store.delete(SESSION_RECORD_ID));
    await sessionStoreRequest("readwrite", (store) => store.delete(SESSION_WRAP_KEY_ID));
  } catch {
    // The page performs the same cleanup; the worker must still clear its memory if storage is unavailable.
  }
}

async function restorePersistedContentKey() {
  try {
    const [record, wrappingKey] = await Promise.all([
      sessionStoreRequest("readonly", (store) => store.get(SESSION_RECORD_ID)),
      sessionStoreRequest("readonly", (store) => store.get(SESSION_WRAP_KEY_ID))
    ]);
    if (
      !record
      || !wrappingKey
      || record.version !== 1
      || !Number.isFinite(record.expiresAt)
      || record.expiresAt <= Date.now()
      || record.expiresAt > Date.now() + MAX_SESSION_MS + 60_000
    ) return false;

    const plain = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: fromBase64(record.iv),
      additionalData: SESSION_AAD
    }, wrappingKey, fromBase64(record.ciphertext));
    const session = JSON.parse(new TextDecoder().decode(plain));
    const raw = fromBase64(session.keyBase64);
    if (
      raw.byteLength !== 32
      || typeof session.keyVersion !== "string"
      || !session.keyVersion
      || session.expiresAt !== record.expiresAt
    ) return false;

    contentKey = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    keyVersion = session.keyVersion;
    keyExpiresAt = session.expiresAt;
    manifestPromise = null;
    return true;
  } catch {
    return false;
  }
}

function finishRecovery(requestId, recovered) {
  if (!recoveryResolver || requestId !== recoveryRequestId) return;
  recoveryResolver(recovered);
}

async function recoverContentKey() {
  if (contentKeyIsValid()) return true;
  clearContentKey();
  if (recoveryPromise) return await recoveryPromise;

  const requestId = ++recoveryRequestId;
  recoveryPromise = (async () => {
    if (await restorePersistedContentKey()) return true;
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (!windows.length) return false;
    return await new Promise((resolve) => {
      let finished = false;
      const finish = (result) => {
        if (finished) return;
        finished = true;
        clearTimeout(timeout);
        recoveryResolver = null;
        resolve(result);
      };
      recoveryResolver = finish;
      const timeout = setTimeout(() => finish(false), 5000);
      for (const client of windows) client.postMessage({ type: "CONTENT_KEY_REQUIRED", requestId });
    });
  })();

  try {
    return Boolean(await recoveryPromise) && contentKeyIsValid();
  } finally {
    recoveryPromise = null;
    recoveryResolver = null;
  }
}

async function notifySessionExpired() {
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const client of windows) client.postMessage({ type: "SESSION_EXPIRED" });
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function aad(logicalPath) {
  return encoder.encode(`iaccess-secure-site:v${FORMAT_VERSION}:${keyVersion}:${logicalPath}`);
}

async function decryptPayload(payload, logicalPath) {
  const bytes = new Uint8Array(payload);
  if (bytes.length < 32 || String.fromCharCode(...bytes.slice(0, 4)) !== "IAE1") throw new Error("Ungueltiges Dateiformat");
  const iv = bytes.slice(4, 16);
  const encryptedAndTag = bytes.slice(16);
  return await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad(logicalPath), tagLength: 128 }, contentKey, encryptedAndTag);
}

async function loadManifest() {
  if (!contentKeyIsValid()) throw new Error("Nicht angemeldet");
  if (!manifestPromise) {
    manifestPromise = (async () => {
      const buildResponse = await fetch(appUrl("secure/build.json"), { cache: "no-store" });
      if (!buildResponse.ok) throw new Error("Build-Information fehlt");
      const build = await buildResponse.json();
      if (build.format !== FORMAT_VERSION || build.keyVersion !== keyVersion) throw new Error("Schluesselversion passt nicht zum Inhalt");
      const response = await fetch(appUrl("secure/manifest.bin"), { cache: "no-store" });
      if (!response.ok) throw new Error("Manifest fehlt");
      const plain = await decryptPayload(await response.arrayBuffer(), "manifest");
      const manifest = JSON.parse(new TextDecoder().decode(plain));
      if (manifest.format !== FORMAT_VERSION || manifest.keyVersion !== keyVersion) throw new Error("Ungueltiges Manifest");
      return manifest;
    })().catch((error) => {
      manifestPromise = null;
      throw error;
    });
  }
  return await manifestPromise;
}

function logicalPath(url) {
  const encoded = url.pathname.slice(SECURE_PREFIX.length);
  const decoded = decodeURIComponent(encoded).replace(/^\/+/, "");
  if (!decoded || decoded.includes("..") || decoded.includes("\\")) return null;
  return decoded;
}

function responseHeaders(mime) {
  return {
    "content-type": mime,
    "cache-control": "no-store, private",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  };
}

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(SECURE_PREFIX)) return;
  event.respondWith((async () => {
    if (!await recoverContentKey()) {
      await notifySessionExpired();
      return new Response("Anmeldung erforderlich", { status: 401, headers: responseHeaders("text/plain; charset=utf-8") });
    }
    const requested = logicalPath(url);
    if (!requested) return new Response("Nicht gefunden", { status: 404 });
    try {
      const manifest = await loadManifest();
      const record = manifest.files[requested];
      if (!record || !/^[a-f0-9]{64}\.bin$/.test(record.blob)) return new Response("Nicht gefunden", { status: 404 });
      const expectedAad = `blob:${record.blob.slice(0, -4)}`;
      if (record.aad !== expectedAad) throw new Error("Ungueltige Blob-Zuordnung");
      const response = await fetch(appUrl(`secure/blobs/${record.blob}`), { cache: "no-store" });
      if (!response.ok) throw new Error("Verschluesselte Datei fehlt");
      const plain = await decryptPayload(await response.arrayBuffer(), record.aad);
      return new Response(plain, { status: 200, headers: responseHeaders(record.mime) });
    } catch {
      return new Response("Geschuetzter Inhalt konnte nicht entschluesselt werden", { status: 503, headers: responseHeaders("text/plain; charset=utf-8") });
    }
  })());
});
