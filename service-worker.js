"use strict";

const FORMAT_VERSION = 2;
const SCOPE_PATH = new URL(self.registration.scope).pathname.replace(/\/$/, "");
const SECURE_PREFIX = `${SCOPE_PATH}/secure-app/`;
const encoder = new TextEncoder();
let contentKey = null;
let keyVersion = null;
let manifestPromise = null;

function appUrl(relative) {
  return `${SCOPE_PATH}/${relative}`;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.type === "CLAIM_CLIENTS") event.waitUntil(self.clients.claim());
  if (data.type === "CLEAR_CONTENT_KEY") {
    contentKey = null;
    keyVersion = null;
    manifestPromise = null;
  }
  if (data.type === "SET_CONTENT_KEY") {
    event.waitUntil((async () => {
      try {
        const raw = fromBase64(data.keyBase64);
        if (raw.byteLength !== 32) throw new Error("Ungueltiger Inhaltsschluessel");
        contentKey = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
        keyVersion = data.keyVersion;
        manifestPromise = null;
        event.ports[0]?.postMessage({ ok: true });
      } catch (error) {
        contentKey = null;
        keyVersion = null;
        manifestPromise = null;
        event.ports[0]?.postMessage({ ok: false });
        throw error;
      }
    })());
  }
});

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
  if (!contentKey || !keyVersion) throw new Error("Nicht angemeldet");
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
    if (!contentKey) return new Response("Anmeldung erforderlich", { status: 401, headers: responseHeaders("text/plain; charset=utf-8") });
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
