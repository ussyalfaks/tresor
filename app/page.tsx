"use client";

import { useState, useEffect, useRef, useCallback } from "react";

const API = "https://whisperbox.koyeb.app";
const subtle = globalThis.crypto.subtle;

// ─── Crypto helpers ───────────────────────────────────────────────────────────

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return await subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]
  );
}

async function exportPublicKey(key: CryptoKey): Promise<string> {
  const buf = await subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function importPublicKey(b64: string): Promise<CryptoKey> {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return await subtle.importKey("spki", buf, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
}

async function deriveWrappingKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const base = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return await subtle.deriveKey(
    { name: "PBKDF2", salt: salt as unknown as Uint8Array<ArrayBuffer>, iterations: 100000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function wrapPrivateKey(privKey: CryptoKey, password: string): Promise<{ wrapped_private_key: string; pbkdf2_salt: string }> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv   = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const wrapKey = await deriveWrappingKey(password, salt);
  const pkcs8   = await subtle.exportKey("pkcs8", privKey);
  const ct      = await subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, pkcs8);
  const blob = new Uint8Array(12 + ct.byteLength);
  blob.set(iv, 0);
  blob.set(new Uint8Array(ct), 12);
  return {
    wrapped_private_key: btoa(String.fromCharCode(...blob)),
    pbkdf2_salt: btoa(String.fromCharCode(...salt)),
  };
}

async function unwrapPrivateKey(wrappedB64: string, saltB64: string, password: string): Promise<CryptoKey> {
  const blob = Uint8Array.from(atob(wrappedB64), c => c.charCodeAt(0));
  const salt = Uint8Array.from(atob(saltB64),    c => c.charCodeAt(0));
  const iv   = blob.slice(0, 12);
  const ct   = blob.slice(12);
  const wrapKey = await deriveWrappingKey(password, salt);
  const pkcs8   = await subtle.decrypt({ name: "AES-GCM", iv }, wrapKey, ct);
  return await subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

async function generateAESKey(): Promise<CryptoKey> {
  return await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]) as CryptoKey;
}

async function exportAESKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

async function importAESKey(bytes: Uint8Array): Promise<CryptoKey> {
  return await subtle.importKey("raw", bytes as unknown as Uint8Array<ArrayBuffer>, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptAES(aesKey: CryptoKey, plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(plaintext));
  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ct))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

async function decryptAES(aesKey: CryptoKey, ciphertextB64: string, ivB64: string): Promise<string> {
  const ct = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const pt = await subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
  return new TextDecoder().decode(pt);
}

async function encryptRSA(pubKey: CryptoKey, data: Uint8Array): Promise<string> {
  const ct = await subtle.encrypt({ name: "RSA-OAEP" }, pubKey, data as unknown as Uint8Array<ArrayBuffer>);
  return btoa(String.fromCharCode(...new Uint8Array(ct)));
}

async function decryptRSA(privKey: CryptoKey, b64: string): Promise<Uint8Array> {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const pt = await subtle.decrypt({ name: "RSA-OAEP" }, privKey, buf);
  return new Uint8Array(pt);
}

// ─── IndexedDB key cache ──────────────────────────────────────────────────────

const DB_NAME = "whisperbox_keys";
const DB_VER  = 1;

function openDB(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = e => {
      (e.target as IDBOpenDBRequest).result.createObjectStore("keys", { keyPath: "username" });
    };
    req.onsuccess = e => res((e.target as IDBOpenDBRequest).result);
    req.onerror   = e => rej((e.target as IDBOpenDBRequest).error);
  });
}

async function cacheKeys(username: string, wrapped_private_key: string, pbkdf2_salt: string, public_key: string): Promise<void> {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").put({ username, wrapped_private_key, pbkdf2_salt, public_key });
    tx.oncomplete = () => res();
    tx.onerror    = e => rej((e.target as IDBTransaction).error);
  });
}

async function getCachedKeys(username: string): Promise<{ wrapped_private_key: string; pbkdf2_salt: string; public_key: string } | null> {
  const db = await openDB();
  return new Promise((res, rej) => {
    const req = db.transaction("keys").objectStore("keys").get(username);
    req.onsuccess = e => res((e.target as IDBRequest).result ?? null);
    req.onerror   = e => rej((e.target as IDBRequest).error);
  });
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiCall(
  endpoint: string,
  method = "GET",
  body: Record<string, unknown> | null = null,
  token: string | null = null
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API}${endpoint}`, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({})) as Record<string, unknown>;
  if (!res.ok) throw new Error((data.detail as string) || (data.message as string) || `HTTP ${res.status}`);
  return data;
}

// ─── Time helpers ─────────────────────────────────────────────────────────────

function formatTime(ts: string | null | undefined): string {
  if (!ts) return "";
  const d = new Date(ts);
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface CurrentUser {
  id: string;
  username: string;
  displayName: string;
  publicKey: CryptoKey;
}

interface ConvEntry {
  user_id: string;
  username: string;
  display_name: string;
  last_message_at: string | null;
}

interface MsgPayload {
  ciphertext: string;
  iv: string;
  encryptedKey: string;
  encryptedKeyForSelf: string;
}

interface ApiMessage {
  id: string;
  from_user_id: string;
  to_user_id: string;
  payload: MsgPayload;
  delivered: boolean;
  created_at: string;
}

interface Message extends ApiMessage {
  plaintext: string | null;
  decryptFailed: boolean;
}

interface ActiveConv {
  userId: string;
  username: string;
  displayName: string;
  publicKey: CryptoKey;
}

interface SearchResult {
  id: string;
  username: string;
  display_name: string;
}

// ─── Avatar ───────────────────────────────────────────────────────────────────

const COLORS = ["#6366f1","#8b5cf6","#ec4899","#14b8a6","#f59e0b","#10b981","#3b82f6","#ef4444"];

function Avatar({ name, size = 36 }: { name: string | null; size?: number }) {
  const idx = (name || "?").charCodeAt(0) % COLORS.length;
  return (
    <div style={{
      width: size, height: size, borderRadius: "50%", background: COLORS[idx],
      display: "flex", alignItems: "center", justifyContent: "center",
      color: "#fff", fontSize: size * 0.38, fontWeight: 600, flexShrink: 0,
      fontFamily: "'DM Mono', monospace",
    }}>{(name || "?").slice(0, 2).toUpperCase()}</div>
  );
}

// ─── Theme CSS ────────────────────────────────────────────────────────────────

const THEME_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--bd2); border-radius: 4px; }
  input, textarea { outline: none; }
  button { cursor: pointer; border: none; background: none; }
  [data-theme="dark"] {
    --bg: #0a0a0f; --surface: #0f0e1a; --elevated: #1a1830;
    --bd: #1e1d2e; --bd2: #2a2840;
    --txt: #e8e6f0; --txt2: #5b5880; --txt3: #3d3b58;
    --accent: #7c3aed; --accent2: #c4b5fd;
    --msg-other: #1a1830; --msg-other-bd: #2a2840;
    --err-bg: #1a0f0f; --err-bd: #3d1515; --status-bg: #120f1a;
    --badge-bg: #1a1030;
  }
  [data-theme="light"] {
    --bg: #f0eeff; --surface: #ffffff; --elevated: #ede9ff;
    --bd: #ddd9f0; --bd2: #c8c4e0;
    --txt: #1a1830; --txt2: #6b6890; --txt3: #a0a0c0;
    --accent: #7c3aed; --accent2: #7c3aed;
    --msg-other: #ede9ff; --msg-other-bd: #c8c4e0;
    --err-bg: #fff0f0; --err-bd: #ffd0d0; --status-bg: #f5f0ff;
    --badge-bg: #e8e4ff;
  }
`;

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function WhisperBox() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [screen, setScreen] = useState<"auth" | "app">("auth");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [token, setToken] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [activeConv, setActiveConv] = useState<ActiveConv | null>(null);
  const [conversations, setConversations] = useState<ConvEntry[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMsg, setNewMsg] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [sidePanel, setSidePanel] = useState<"convs" | "new">("convs");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const tokenRef = useRef<string | null>(null);
  const refreshTokenRef = useRef<string | null>(null);
  const activeConvRef = useRef<ActiveConv | null>(null);
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const currentUserRef = useRef<CurrentUser | null>(null);
  const loadConvsRef = useRef<(() => void) | null>(null);

  useEffect(() => { tokenRef.current = token; }, [token]);
  useEffect(() => { refreshTokenRef.current = refreshToken; }, [refreshToken]);
  useEffect(() => { activeConvRef.current = activeConv; }, [activeConv]);
  useEffect(() => { privateKeyRef.current = privateKey; }, [privateKey]);
  useEffect(() => { currentUserRef.current = currentUser; }, [currentUser]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function toggleTheme() { setTheme(t => t === "dark" ? "light" : "dark"); }

  // ─── Auth ──────────────────────────────────────────────────────────────────

  async function handleRegister(username: string, displayName: string, password: string) {
    setLoading(true); setError("");
    try {
      setStatus("Generating encryption keys…");
      const kp = await generateKeyPair();
      const pubB64 = await exportPublicKey(kp.publicKey);
      const { wrapped_private_key, pbkdf2_salt } = await wrapPrivateKey(kp.privateKey, password);

      setStatus("Creating account…");
      const res = await apiCall("/auth/register", "POST", {
        username,
        display_name: displayName || username,
        password,
        public_key: pubB64,
        wrapped_private_key,
        pbkdf2_salt,
      });

      const tok = res.access_token as string;
      const refTok = res.refresh_token as string;
      const user = res.user as { id: string; username: string; display_name: string };

      await cacheKeys(username, wrapped_private_key, pbkdf2_salt, pubB64);

      setToken(tok);
      setRefreshToken(refTok);
      setCurrentUser({ id: user.id, username: user.username, displayName: user.display_name, publicKey: kp.publicKey });
      setPrivateKey(kp.privateKey);
      setScreen("app");
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); setStatus(""); }
  }

  async function handleLogin(username: string, password: string) {
    setLoading(true); setError("");
    try {
      setStatus("Authenticating…");
      const res = await apiCall("/auth/login", "POST", { username, password });
      const tok = res.access_token as string;
      const refTok = res.refresh_token as string;
      const user = res.user as {
        id: string; username: string; display_name: string;
        public_key: string; wrapped_private_key: string; pbkdf2_salt: string;
      };

      setStatus("Unlocking keys…");
      const cached = await getCachedKeys(username).catch(() => null);
      const wrappedKey = cached?.wrapped_private_key ?? user.wrapped_private_key;
      const salt       = cached?.pbkdf2_salt         ?? user.pbkdf2_salt;
      const pubKeyB64  = cached?.public_key           ?? user.public_key;

      const [privKey, pubKey] = await Promise.all([
        unwrapPrivateKey(wrappedKey, salt, password),
        importPublicKey(pubKeyB64),
      ]);

      await cacheKeys(username, user.wrapped_private_key, user.pbkdf2_salt, user.public_key);

      setToken(tok);
      setRefreshToken(refTok);
      setCurrentUser({ id: user.id, username: user.username, displayName: user.display_name, publicKey: pubKey });
      setPrivateKey(privKey);
      setScreen("app");
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); setStatus(""); }
  }

  function handleLogout() {
    if (pollRef.current) clearInterval(pollRef.current);
    wsRef.current?.close();
    wsRef.current = null;
    setToken(null); setRefreshToken(null); setCurrentUser(null); setPrivateKey(null);
    setScreen("auth"); setConversations([]); setMessages([]); setActiveConv(null);
  }

  // Refresh access token every 13 minutes
  useEffect(() => {
    if (screen !== "app") return;
    const interval = setInterval(async () => {
      const refTok = refreshTokenRef.current;
      if (!refTok) return;
      try {
        const res = await apiCall("/auth/refresh", "POST", { refresh_token: refTok });
        setToken(res.access_token as string);
      } catch { handleLogout(); }
    }, 13 * 60 * 1000);
    return () => clearInterval(interval);
  }, [screen]);

  // ─── WebSocket ─────────────────────────────────────────────────────────────

  const handleWSMessage = useCallback(async (raw: Record<string, unknown>) => {
    if (raw.event !== "message.receive") return;
    const msg = raw as unknown as ApiMessage & { event: string };
    const conv = activeConvRef.current;
    const privKey = privateKeyRef.current;
    const me = currentUserRef.current;
    if (!privKey || !me) return;

    const otherId = msg.from_user_id === me.id ? msg.to_user_id : msg.from_user_id;
    if (!conv || otherId !== conv.userId) {
      loadConvsRef.current?.();
      return;
    }

    try {
      const keyToUse = msg.from_user_id === me.id ? msg.payload.encryptedKeyForSelf : msg.payload.encryptedKey;
      const aesKeyBytes = await decryptRSA(privKey, keyToUse);
      const aesKey = await importAESKey(aesKeyBytes);
      const plaintext = await decryptAES(aesKey, msg.payload.ciphertext, msg.payload.iv);
      setMessages(prev => prev.some(m => m.id === msg.id) ? prev : [...prev, { ...msg, plaintext, decryptFailed: false }]);
    } catch {
      setMessages(prev => prev.some(m => m.id === msg.id) ? prev : [...prev, { ...msg, plaintext: null, decryptFailed: true }]);
    }
    loadConvsRef.current?.();
  }, []);

  useEffect(() => {
    if (screen !== "app" || !token) return;
    const ws = new WebSocket(`wss://whisperbox.koyeb.app/ws?token=${token}`);
    wsRef.current = ws;
    ws.onmessage = (e) => {
      try { handleWSMessage(JSON.parse(e.data) as Record<string, unknown>); } catch { /* ignore */ }
    };
    return () => { ws.close(); wsRef.current = null; };
  }, [screen, token, handleWSMessage]);

  // ─── Conversations ─────────────────────────────────────────────────────────

  const loadConversations = useCallback(async () => {
    if (!tokenRef.current) return;
    try {
      const res = await apiCall("/conversations", "GET", null, tokenRef.current);
      setConversations((res as unknown as ConvEntry[]) || []);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { loadConvsRef.current = loadConversations; }, [loadConversations]);

  useEffect(() => {
    if (screen === "app") {
      loadConversations();
      pollRef.current = setInterval(loadConversations, 10000);
      return () => { if (pollRef.current) clearInterval(pollRef.current); };
    }
  }, [screen, loadConversations]);

  // ─── User search & conversation start ──────────────────────────────────────

  async function searchUsers(q: string) {
    if (!q.trim() || !token) { setSearchResults([]); return; }
    try {
      const res = await apiCall(`/users/search?q=${encodeURIComponent(q.trim())}`, "GET", null, token);
      setSearchResults((res as unknown as SearchResult[]) || []);
    } catch { setSearchResults([]); }
  }

  async function startConversation(result: SearchResult) {
    setLoading(true); setError("");
    try {
      const keyRes = await apiCall(`/users/${result.id}/public-key`, "GET", null, token);
      const pubKey = await importPublicKey(keyRes.public_key as string);
      setActiveConv({ userId: result.id, username: result.username, displayName: result.display_name, publicKey: pubKey });
      setMessages([]);
      setSearchInput(""); setSearchResults([]);
      setSidePanel("convs");
      await loadConversations();
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }

  async function openConversation(conv: ConvEntry) {
    setLoading(true); setError("");
    try {
      const keyRes = await apiCall(`/users/${conv.user_id}/public-key`, "GET", null, token);
      const pubKey = await importPublicKey(keyRes.public_key as string);
      setActiveConv({ userId: conv.user_id, username: conv.username, displayName: conv.display_name, publicKey: pubKey });
      setMessages([]);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }

  // ─── Messages ──────────────────────────────────────────────────────────────

  const loadMessages = useCallback(async () => {
    if (!token || !activeConv || !privateKey || !currentUser) return;
    try {
      const res = await apiCall(`/conversations/${activeConv.userId}/messages`, "GET", null, token);
      const msgs = [...((res as unknown as ApiMessage[]) || [])].reverse();
      const decrypted = await Promise.all(msgs.map(async (m): Promise<Message> => {
        try {
          const keyToUse = m.from_user_id === currentUser.id ? m.payload.encryptedKeyForSelf : m.payload.encryptedKey;
          const aesKeyBytes = await decryptRSA(privateKey, keyToUse);
          const aesKey = await importAESKey(aesKeyBytes);
          const plaintext = await decryptAES(aesKey, m.payload.ciphertext, m.payload.iv);
          return { ...m, plaintext, decryptFailed: false };
        } catch {
          return { ...m, plaintext: null, decryptFailed: true };
        }
      }));
      setMessages(decrypted);
    } catch { /* silent */ }
  }, [token, activeConv, privateKey, currentUser]);

  useEffect(() => {
    if (!activeConv) return;
    loadMessages();
    const interval = setInterval(loadMessages, 5000);
    return () => clearInterval(interval);
  }, [activeConv, loadMessages]);

  async function sendMessage() {
    if (!newMsg.trim() || !activeConv || !currentUser || !privateKey) return;
    setLoading(true);
    try {
      const aesKey = await generateAESKey();
      const aesKeyBytes = await exportAESKey(aesKey);
      const { ciphertext, iv } = await encryptAES(aesKey, newMsg.trim());
      const [encryptedKey, encryptedKeyForSelf] = await Promise.all([
        encryptRSA(activeConv.publicKey, aesKeyBytes),
        encryptRSA(currentUser.publicKey, aesKeyBytes),
      ]);
      const payload = { ciphertext, iv, encryptedKey, encryptedKeyForSelf };

      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ event: "message.send", to: activeConv.userId, payload }));
      } else {
        await apiCall("/messages", "POST", { to: activeConv.userId, payload }, token);
      }

      setNewMsg("");
      await loadMessages();
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }

  // ─── UI ────────────────────────────────────────────────────────────────────

  if (screen === "auth") return (
    <AuthScreen
      authMode={authMode}
      setAuthMode={setAuthMode}
      onLogin={handleLogin}
      onRegister={handleRegister}
      loading={loading}
      error={error}
      status={status}
      theme={theme}
      onToggleTheme={toggleTheme}
    />
  );

  return (
    <div data-theme={theme} style={{ display: "flex", height: "100vh", background: "var(--bg)", fontFamily: "'DM Sans', system-ui, sans-serif", color: "var(--txt)", overflow: "hidden" }}>
      <style>{THEME_CSS}</style>

      {/* Sidebar */}
      <div style={{ width: 280, background: "var(--surface)", borderRight: "1px solid var(--bd)", display: "flex", flexDirection: "column", flexShrink: 0 }}>
        <div style={{ padding: "20px 16px 16px", borderBottom: "1px solid var(--bd)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <img src="/tresor1.png" alt="Tresor" style={{ width: 28, height: 28, borderRadius: 8, objectFit: "cover", flexShrink: 0 }} />
            <span style={{ fontSize: 15, fontWeight: 600, fontFamily: "'DM Mono', monospace", color: "var(--accent2)" }}>Tresor</span>
            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#10b981" }} title="E2EE Active" />
              <button
                onClick={toggleTheme}
                title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
                style={{
                  width: 28, height: 28, borderRadius: 7,
                  background: "var(--elevated)", border: "1px solid var(--bd)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 14, flexShrink: 0, transition: "background 0.15s",
                }}
              >
                {theme === "dark" ? "☀️" : "🌙"}
              </button>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Avatar name={currentUser?.displayName || currentUser?.username || null} size={32} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: "var(--txt)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{currentUser?.displayName || currentUser?.username}</div>
              <div style={{ fontSize: 11, color: "var(--txt3)", fontFamily: "'DM Mono', monospace" }}>end-to-end encrypted</div>
            </div>
            <button onClick={handleLogout} style={{ fontSize: 11, color: "var(--txt2)", padding: "4px 8px", borderRadius: 6, border: "1px solid var(--bd)" }}>out</button>
          </div>
        </div>

        <div style={{ display: "flex", borderBottom: "1px solid var(--bd)" }}>
          {(["convs", "new"] as const).map(v => (
            <button key={v} onClick={() => setSidePanel(v)} style={{
              flex: 1, padding: "10px 0", fontSize: 12, fontWeight: 500,
              color: sidePanel === v ? "var(--accent2)" : "var(--txt2)",
              borderBottom: sidePanel === v ? "2px solid var(--accent)" : "2px solid transparent",
              transition: "all 0.15s",
            }}>{v === "convs" ? "Chats" : "New Chat"}</button>
          ))}
        </div>

        {sidePanel === "convs" ? (
          <div style={{ flex: 1, overflowY: "auto" }}>
            {conversations.length === 0 ? (
              <div style={{ padding: 24, textAlign: "center", color: "var(--txt3)", fontSize: 13 }}>
                No conversations yet.<br />Start a new chat →
              </div>
            ) : conversations.map(conv => {
              const isActive = activeConv?.userId === conv.user_id;
              const name = conv.display_name || conv.username;
              return (
                <button key={conv.user_id} onClick={() => openConversation(conv)} style={{
                  display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "12px 16px",
                  background: isActive ? "var(--elevated)" : "transparent",
                  borderLeft: isActive ? "3px solid var(--accent)" : "3px solid transparent",
                  transition: "all 0.1s", textAlign: "left",
                }}>
                  <Avatar name={name} size={38} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, color: "var(--txt)", marginBottom: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{name}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <span style={{ fontSize: 9, color: "var(--accent)", fontFamily: "'DM Mono', monospace", background: "var(--badge-bg)", padding: "1px 5px", borderRadius: 3 }}>🔒 E2EE</span>
                      <span style={{ fontSize: 11, color: "var(--txt3)" }}>{formatTime(conv.last_message_at)}</span>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        ) : (
          <div style={{ flex: 1, padding: 16, overflowY: "auto" }}>
            <div style={{ fontSize: 12, color: "var(--txt2)", marginBottom: 12, fontFamily: "'DM Mono', monospace" }}>FIND A USER</div>
            <input
              value={searchInput}
              onChange={e => { setSearchInput(e.target.value); searchUsers(e.target.value); }}
              placeholder="Search by username…"
              style={{ width: "100%", padding: "10px 12px", background: "var(--bg)", border: "1px solid var(--bd2)", borderRadius: 8, color: "var(--txt)", fontSize: 13, marginBottom: 10 }}
            />
            {error && <div style={{ fontSize: 12, color: "#f87171", marginBottom: 8 }}>{error}</div>}
            {searchResults.map(r => (
              <button key={r.id} onClick={() => startConversation(r)} disabled={loading} style={{
                display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "10px 12px",
                background: "var(--elevated)", borderRadius: 8, marginBottom: 6, textAlign: "left",
                opacity: loading ? 0.6 : 1,
              }}>
                <Avatar name={r.display_name || r.username} size={32} />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500, color: "var(--txt)" }}>{r.display_name}</div>
                  <div style={{ fontSize: 11, color: "var(--txt2)", fontFamily: "'DM Mono', monospace" }}>@{r.username}</div>
                </div>
              </button>
            ))}
            {searchInput && searchResults.length === 0 && (
              <div style={{ fontSize: 12, color: "var(--txt3)", textAlign: "center", marginTop: 16 }}>No users found</div>
            )}
          </div>
        )}
      </div>

      {/* Main Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {activeConv ? (
          <>
            <div style={{ padding: "14px 20px", background: "var(--surface)", borderBottom: "1px solid var(--bd)", display: "flex", alignItems: "center", gap: 12 }}>
              <Avatar name={activeConv.displayName || activeConv.username} size={38} />
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: "var(--txt)" }}>{activeConv.displayName || activeConv.username}</div>
                <div style={{ fontSize: 11, color: "var(--accent)", fontFamily: "'DM Mono', monospace" }}>
                  🔒 End-to-end encrypted · RSA-OAEP + AES-256-GCM
                </div>
              </div>
              <div style={{ marginLeft: "auto", fontSize: 11, color: "var(--txt3)", fontFamily: "'DM Mono', monospace" }}>
                @{activeConv.username}
              </div>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "20px 20px 8px", display: "flex", flexDirection: "column", gap: 12 }}>
              {messages.length === 0 && (
                <div style={{ textAlign: "center", padding: "60px 20px", color: "var(--txt3)" }}>
                  <div style={{ fontSize: 32, marginBottom: 12 }}>🔐</div>
                  <div style={{ fontSize: 14, color: "var(--txt2)", marginBottom: 6 }}>This conversation is end-to-end encrypted</div>
                  <div style={{ fontSize: 12, color: "var(--txt3)" }}>Only you and {activeConv.displayName || activeConv.username} can read these messages.</div>
                </div>
              )}
              {messages.map((m, i) => {
                const isMine = m.from_user_id === currentUser?.id;
                return (
                  <div key={m.id || i} style={{ display: "flex", flexDirection: "column", alignItems: isMine ? "flex-end" : "flex-start" }}>
                    <div style={{ maxWidth: "70%", display: "flex", flexDirection: isMine ? "row-reverse" : "row", gap: 8, alignItems: "flex-end" }}>
                      {!isMine && <Avatar name={activeConv.displayName || activeConv.username} size={28} />}
                      <div>
                        <div style={{
                          padding: "10px 14px",
                          borderRadius: isMine ? "18px 18px 4px 18px" : "18px 18px 18px 4px",
                          background: isMine ? "#4f46e5" : "var(--msg-other)",
                          border: isMine ? "none" : "1px solid var(--msg-other-bd)",
                          fontSize: 14, color: m.decryptFailed ? "#f87171" : (isMine ? "#ffffff" : "var(--txt)"),
                          lineHeight: 1.5, wordBreak: "break-word",
                        }}>
                          {m.decryptFailed ? "⚠ Unable to decrypt" : (m.plaintext || "…")}
                        </div>
                        <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 4, justifyContent: isMine ? "flex-end" : "flex-start" }}>
                          <span style={{ fontSize: 10, color: "var(--txt3)" }}>{formatTime(m.created_at)}</span>
                          {!m.decryptFailed && <span style={{ fontSize: 10, color: "var(--accent)", fontFamily: "'DM Mono', monospace" }}>🔒 decrypted</span>}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            <div style={{ padding: "12px 20px", background: "var(--surface)", borderTop: "1px solid var(--bd)" }}>
              {error && <div style={{ fontSize: 12, color: "#f87171", marginBottom: 8 }}>{error}</div>}
              <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
                <div style={{ flex: 1, background: "var(--bg)", border: "1px solid var(--bd2)", borderRadius: 12, padding: "10px 14px", display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 12, color: "var(--txt2)", flexShrink: 0 }}>🔒</span>
                  <input
                    value={newMsg}
                    onChange={e => setNewMsg(e.target.value)}
                    onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                    placeholder="Type an encrypted message…"
                    style={{ flex: 1, background: "none", border: "none", color: "var(--txt)", fontSize: 14, fontFamily: "'DM Sans', system-ui, sans-serif" }}
                  />
                </div>
                <button onClick={sendMessage} disabled={loading || !newMsg.trim()} style={{
                  width: 42, height: 42, borderRadius: 12,
                  background: newMsg.trim() ? "var(--accent)" : "var(--bd)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 16, flexShrink: 0, transition: "all 0.15s", opacity: loading ? 0.6 : 1,
                }}>↑</button>
              </div>
              <div style={{ textAlign: "center", fontSize: 10, color: "var(--txt3)", marginTop: 8, fontFamily: "'DM Mono', monospace" }}>
                Encrypted with AES-256-GCM · Keys never leave your device
              </div>
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16 }}>
            <div style={{ fontSize: 48 }}>🔐</div>
            <div style={{ fontSize: 18, fontWeight: 600, color: "var(--accent2)" }}>Select a conversation</div>
            <div style={{ fontSize: 13, color: "var(--txt3)", textAlign: "center", maxWidth: 300, lineHeight: 1.6 }}>
              Your messages are encrypted end-to-end. Only you and your recipient can read them.
            </div>
            <EncryptionBadge />
          </div>
        )}
      </div>
    </div>
  );
}

function EncryptionBadge() {
  return (
    <div style={{ background: "var(--surface)", border: "1px solid var(--bd)", borderRadius: 12, padding: "16px 20px", maxWidth: 320 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent)", fontFamily: "'DM Mono', monospace", marginBottom: 12 }}>ENCRYPTION PROTOCOL</div>
      {[
        ["RSA-OAEP 2048", "Key exchange"],
        ["AES-256-GCM", "Message encryption"],
        ["PBKDF2 + AES-GCM", "Key wrapping"],
        ["WebSocket", "Real-time delivery"],
      ].map(([tech, desc]) => (
        <div key={tech} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid var(--bd)" }}>
          <span style={{ fontSize: 12, fontFamily: "'DM Mono', monospace", color: "var(--accent2)" }}>{tech}</span>
          <span style={{ fontSize: 12, color: "var(--txt2)" }}>{desc}</span>
        </div>
      ))}
    </div>
  );
}

interface AuthScreenProps {
  authMode: "login" | "register";
  setAuthMode: (mode: "login" | "register") => void;
  onLogin: (username: string, password: string) => void;
  onRegister: (username: string, displayName: string, password: string) => void;
  loading: boolean;
  error: string;
  status: string;
  theme: "dark" | "light";
  onToggleTheme: () => void;
}

function AuthScreen({ authMode, setAuthMode, onLogin, onRegister, loading, error, status, theme, onToggleTheme }: AuthScreenProps) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [validationError, setValidationError] = useState("");

  const handleSubmit = () => {
    setValidationError("");
    const u = username.trim();
    if (!u || !password) return;
    if (authMode === "register") {
      if (!/^[a-zA-Z0-9_-]{3,32}$/.test(u)) {
        setValidationError("Username must be 3–32 characters: letters, digits, _ or - only.");
        return;
      }
      if (password.length < 8) {
        setValidationError("Password must be at least 8 characters.");
        return;
      }
      onRegister(u, displayName.trim(), password);
    } else {
      onLogin(u, password);
    }
  };

  return (
    <div data-theme={theme} style={{ minHeight: "100vh", background: "var(--bg)", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'DM Sans', system-ui, sans-serif", position: "relative" }}>
      <style>{`
        ${THEME_CSS}
        input { outline: none; }
      `}</style>

      {/* Theme toggle — top right */}
      <button
        onClick={onToggleTheme}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        style={{
          position: "absolute", top: 20, right: 20,
          width: 36, height: 36, borderRadius: 10,
          background: "var(--surface)", border: "1px solid var(--bd)",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 16, cursor: "pointer", transition: "background 0.15s",
        }}
      >
        {theme === "dark" ? "☀️" : "🌙"}
      </button>

      <div style={{ width: 380 }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <img src="/tresor1.png" alt="Tresor" style={{ width: 130, borderRadius: 20, margin: "0 auto 12px", display: "block" }} />
          <div style={{ fontSize: 13, color: "var(--txt2)" }}>End-to-end encrypted messaging</div>
        </div>

        <div style={{ background: "var(--surface)", border: "1px solid var(--bd)", borderRadius: 16, padding: 28 }}>
          <div style={{ display: "flex", background: "var(--bg)", borderRadius: 10, padding: 3, marginBottom: 24 }}>
            {(["login", "register"] as const).map(v => (
              <button key={v} onClick={() => setAuthMode(v)} style={{
                flex: 1, padding: "8px 0", fontSize: 13, fontWeight: 500, borderRadius: 8,
                background: authMode === v ? "var(--accent)" : "transparent",
                color: authMode === v ? "#fff" : "var(--txt2)", transition: "all 0.15s",
              }}>{v === "login" ? "Sign In" : "Register"}</button>
            ))}
          </div>

          {authMode === "register" && (
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 12, color: "var(--txt2)", display: "block", marginBottom: 6, fontFamily: "'DM Mono', monospace" }}>DISPLAY NAME</label>
              <input value={displayName} onChange={e => setDisplayName(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleSubmit()}
                placeholder="Your Name"
                style={{ width: "100%", padding: "11px 14px", background: "var(--bg)", border: "1px solid var(--bd2)", borderRadius: 10, color: "var(--txt)", fontSize: 14 }} />
            </div>
          )}

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--txt2)", display: "block", marginBottom: 6, fontFamily: "'DM Mono', monospace" }}>USERNAME</label>
            <input value={username} onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSubmit()}
              placeholder="your_username"
              style={{ width: "100%", padding: "11px 14px", background: "var(--bg)", border: "1px solid var(--bd2)", borderRadius: 10, color: "var(--txt)", fontSize: 14, fontFamily: "'DM Mono', monospace" }} />
          </div>
          <div style={{ marginBottom: 20 }}>
            <label style={{ fontSize: 12, color: "var(--txt2)", display: "block", marginBottom: 6, fontFamily: "'DM Mono', monospace" }}>PASSWORD</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSubmit()}
              placeholder="••••••••"
              style={{ width: "100%", padding: "11px 14px", background: "var(--bg)", border: "1px solid var(--bd2)", borderRadius: 10, color: "var(--txt)", fontSize: 14 }} />
          </div>

          {(validationError || error) && <div style={{ fontSize: 13, color: "#f87171", marginBottom: 14, padding: "10px 12px", background: "var(--err-bg)", borderRadius: 8, border: "1px solid var(--err-bd)" }}>{validationError || error}</div>}
          {status && <div style={{ fontSize: 13, color: "var(--accent2)", marginBottom: 14, padding: "10px 12px", background: "var(--status-bg)", borderRadius: 8, border: "1px solid var(--bd)", fontFamily: "'DM Mono', monospace" }}>⟳ {status}</div>}

          <button onClick={handleSubmit} disabled={loading || !username || !password} style={{
            width: "100%", padding: "12px", background: "var(--accent)", borderRadius: 10,
            color: "#fff", fontSize: 14, fontWeight: 600,
            opacity: (loading || !username || !password) ? 0.6 : 1, transition: "all 0.15s",
          }}>
            {loading ? "Working…" : authMode === "register" ? "Create Account" : "Sign In"}
          </button>

          {authMode === "register" && (
            <div style={{ marginTop: 16, padding: 12, background: "var(--bg)", borderRadius: 8, border: "1px solid var(--bd)" }}>
              <div style={{ fontSize: 11, color: "var(--txt2)", lineHeight: 1.7 }}>
                🔑 RSA-2048 keypair generated locally.<br />
                Private key is wrapped with AES-KW (PBKDF2) — it cannot be read without your password.
              </div>
            </div>
          )}
        </div>

        <div style={{ textAlign: "center", marginTop: 20, fontSize: 11, color: "var(--txt3)", fontFamily: "'DM Mono', monospace" }}>
          Zero-knowledge · Server sees only ciphertext
        </div>
      </div>
    </div>
  );
}
