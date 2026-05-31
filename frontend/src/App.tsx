import { useState, useEffect, useCallback } from "react";
import { AuthProvider, useAuth } from "./hooks/useAuth";
import { api } from "./api/client";
import { encrypt, decrypt, generatePassword } from "./utils/crypto";
import { registerBiometric, authenticateBiometric } from "./api/webauthn";

// ── types ────────────────────────────────────────────────────────────────────

type LoginType = "email_password" | "google_sso" | "github_sso" | "apple_sso" | "microsoft_sso" | "other";

interface VaultEntry {
  id: string;
  site_name: string;
  site_url?: string;
  login_type: LoginType;
  encrypted_username?: string;
  encrypted_password?: string;
  encrypted_notes?: string;
  favicon_url?: string;
  created_at: string;
  updated_at: string;
  // decrypted fields (client-only)
  _username?: string;
  _password?: string;
  _notes?: string;
}

const LOGIN_TYPE_LABELS: Record<LoginType, { label: string; icon: string }> = {
  email_password: { label: "Email / Password", icon: "✉️" },
  google_sso: { label: "Sign in with Google", icon: "🟢" },
  github_sso: { label: "Sign in with GitHub", icon: "🐙" },
  apple_sso: { label: "Sign in with Apple", icon: "🍎" },
  microsoft_sso: { label: "Sign in with Microsoft", icon: "🪟" },
  other: { label: "Other", icon: "🔑" },
};

// ── Login / Register Screen ───────────────────────────────────────────────────

function AuthScreen() {
  const { login, loginWithToken } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined" && window.PublicKeyCredential) {
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then(setBiometricAvailable);
    }
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (mode === "register") {
        const data = await api.auth.register(username, password);
        await loginWithToken(data.token, data.username, password);
      } else {
        await login(username, password);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleBiometric() {
    if (!username) { setError("Enter your username first"); return; }
    setError("");
    setLoading(true);
    try {
      const data = await authenticateBiometric(username);
      // Biometric login doesn't give us the master password for key derivation
      // We need to ask for it once after biometric auth
      const mp = prompt("Enter master password to decrypt vault (needed once per session):");
      if (!mp) return;
      await loginWithToken(data.token, data.username, mp);
    } catch (err: any) {
      setError(err.message || "Biometric authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.authWrap}>
      <div style={styles.authCard}>
        <div style={styles.authLogo}>🔐</div>
        <h1 style={styles.authTitle}>Personal Vault</h1>
        <p style={styles.authSub}>Your passwords, encrypted & yours alone.</p>

        <div style={styles.tabRow}>
          {(["login", "register"] as const).map(m => (
            <button key={m} style={{ ...styles.tab, ...(mode === m ? styles.tabActive : {}) }}
              onClick={() => setMode(m)}>
              {m === "login" ? "Sign In" : "Create Vault"}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} style={styles.form}>
          <input style={styles.input} placeholder="Username" value={username}
            onChange={e => setUsername(e.target.value)} autoFocus required />
          <input style={styles.input} type="password" placeholder="Master Password"
            value={password} onChange={e => setPassword(e.target.value)} required />
          {error && <p style={styles.error}>{error}</p>}
          <button style={styles.btn} type="submit" disabled={loading}>
            {loading ? "…" : mode === "login" ? "Unlock Vault" : "Create Vault"}
          </button>
        </form>

        {mode === "login" && biometricAvailable && (
          <button style={styles.biometricBtn} onClick={handleBiometric} disabled={loading}>
            <span style={{ fontSize: 20 }}>👆</span> Use Touch ID / Face ID
          </button>
        )}

        <p style={styles.zeroKnowledge}>
          🛡️ Zero-knowledge — your passwords are encrypted in your browser before being stored. We never see them.
        </p>
      </div>
    </div>
  );
}

// ── Entry Form ────────────────────────────────────────────────────────────────

function EntryForm({ entry, onSave, onCancel, vaultKey }: {
  entry?: VaultEntry | null;
  onSave: () => void;
  onCancel: () => void;
  vaultKey: CryptoKey;
}) {
  const [siteName, setSiteName] = useState(entry?.site_name || "");
  const [siteUrl, setSiteUrl] = useState(entry?.site_url || "");
  const [loginType, setLoginType] = useState<LoginType>(entry?.login_type || "email_password");
  const [entryUsername, setEntryUsername] = useState(entry?._username || "");
  const [entryPassword, setEntryPassword] = useState(entry?._password || "");
  const [notes, setNotes] = useState(entry?._notes || "");
  const [showPassword, setShowPassword] = useState(false);
  const [saving, setSaving] = useState(false);
  const [genOptions, setGenOptions] = useState({ upper: true, lower: true, numbers: true, symbols: true });
  const [genLength, setGenLength] = useState(20);

  function generatePw() {
    setEntryPassword(generatePassword(genLength, genOptions));
    setShowPassword(true);
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const [enc_user, enc_pass, enc_notes] = await Promise.all([
        entryUsername ? encrypt(entryUsername, vaultKey) : Promise.resolve(""),
        entryPassword ? encrypt(entryPassword, vaultKey) : Promise.resolve(""),
        notes ? encrypt(notes, vaultKey) : Promise.resolve(""),
      ]);

      const payload = {
        site_name: siteName,
        site_url: siteUrl || undefined,
        login_type: loginType,
        encrypted_username: enc_user || undefined,
        encrypted_password: enc_pass || undefined,
        encrypted_notes: enc_notes || undefined,
      };

      if (entry?.id) {
        await api.vault.update(entry.id, payload);
      } else {
        await api.vault.create(payload);
      }
      onSave();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={styles.modal}>
      <div style={styles.modalCard}>
        <h2 style={styles.modalTitle}>{entry ? "Edit Entry" : "New Entry"}</h2>
        <form onSubmit={handleSave} style={styles.form}>
          <input style={styles.input} placeholder="Site Name (e.g. GitHub)" value={siteName}
            onChange={e => setSiteName(e.target.value)} required />
          <input style={styles.input} placeholder="URL (optional)" value={siteUrl}
            onChange={e => setSiteUrl(e.target.value)} />

          <select style={styles.input} value={loginType}
            onChange={e => setLoginType(e.target.value as LoginType)}>
            {Object.entries(LOGIN_TYPE_LABELS).map(([k, v]) => (
              <option key={k} value={k}>{v.icon} {v.label}</option>
            ))}
          </select>

          {loginType === "email_password" && <>
            <input style={styles.input} placeholder="Email / Username" value={entryUsername}
              onChange={e => setEntryUsername(e.target.value)} />
            <div style={styles.pwRow}>
              <input style={{ ...styles.input, flex: 1, marginBottom: 0 }}
                type={showPassword ? "text" : "password"}
                placeholder="Password" value={entryPassword}
                onChange={e => setEntryPassword(e.target.value)} />
              <button type="button" style={styles.iconBtn} onClick={() => setShowPassword(s => !s)}>
                {showPassword ? "🙈" : "👁️"}
              </button>
            </div>
            <div style={styles.genRow}>
              <button type="button" style={styles.genBtn} onClick={generatePw}>⚡ Generate</button>
              <input type="range" min={8} max={64} value={genLength}
                onChange={e => setGenLength(+e.target.value)} style={{ flex: 1 }} />
              <span style={styles.genLen}>{genLength}</span>
            </div>
          </>}

          {loginType !== "email_password" && (
            <input style={styles.input} placeholder="Email used to sign in (optional)"
              value={entryUsername} onChange={e => setEntryUsername(e.target.value)} />
          )}

          <textarea style={{ ...styles.input, height: 80, resize: "vertical" }}
            placeholder="Notes (optional)" value={notes}
            onChange={e => setNotes(e.target.value)} />

          <div style={styles.modalActions}>
            <button type="button" style={styles.cancelBtn} onClick={onCancel}>Cancel</button>
            <button type="submit" style={styles.btn} disabled={saving}>
              {saving ? "Saving…" : "Save Entry"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Entry Card ────────────────────────────────────────────────────────────────

function EntryCard({ entry, onEdit, onDelete }: {
  entry: VaultEntry;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [showPw, setShowPw] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  async function copy(text: string | undefined, label: string) {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  }

  const { icon } = LOGIN_TYPE_LABELS[entry.login_type] || LOGIN_TYPE_LABELS.other;

  return (
    <div style={styles.card}>
      <div style={styles.cardHeader}>
        <div style={styles.cardSite}>
          <span style={styles.cardIcon}>{icon}</span>
          <div>
            <div style={styles.cardName}>{entry.site_name}</div>
            {entry.site_url && (
              <a href={entry.site_url} target="_blank" rel="noopener noreferrer" style={styles.cardUrl}>
                {entry.site_url}
              </a>
            )}
          </div>
        </div>
        <div style={styles.cardActions}>
          <button style={styles.iconBtn} onClick={onEdit} title="Edit">✏️</button>
          <button style={styles.iconBtn} onClick={onDelete} title="Delete">🗑️</button>
        </div>
      </div>

      {entry._username && (
        <div style={styles.fieldRow}>
          <span style={styles.fieldLabel}>Username</span>
          <span style={styles.fieldValue}>{entry._username}</span>
          <button style={styles.copyBtn} onClick={() => copy(entry._username, "username")}>
            {copied === "username" ? "✅" : "📋"}
          </button>
        </div>
      )}

      {entry._password && (
        <div style={styles.fieldRow}>
          <span style={styles.fieldLabel}>Password</span>
          <span style={styles.fieldValue}>
            {showPw ? entry._password : "••••••••••••"}
          </span>
          <button style={styles.iconBtn} onClick={() => setShowPw(s => !s)}>
            {showPw ? "🙈" : "👁️"}
          </button>
          <button style={styles.copyBtn} onClick={() => copy(entry._password, "password")}>
            {copied === "password" ? "✅" : "📋"}
          </button>
        </div>
      )}

      {entry._notes && (
        <div style={{ ...styles.fieldRow, alignItems: "flex-start" }}>
          <span style={styles.fieldLabel}>Notes</span>
          <span style={{ ...styles.fieldValue, whiteSpace: "pre-wrap", flex: 1 }}>{entry._notes}</span>
        </div>
      )}

      {entry.login_type !== "email_password" && !entry._username && (
        <div style={styles.ssoTag}>
          {LOGIN_TYPE_LABELS[entry.login_type].label}
        </div>
      )}
    </div>
  );
}

// ── Main Vault App ─────────────────────────────────────────────────────────────

function VaultApp() {
  const { vaultKey, logout, username } = useAuth();
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [editEntry, setEditEntry] = useState<VaultEntry | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [devices, setDevices] = useState<any[]>([]);

  const loadEntries = useCallback(async () => {
    if (!vaultKey) return;
    setLoading(true);
    try {
      const raw = await api.vault.list();
      const decrypted = await Promise.all(raw.map(async (e: VaultEntry) => ({
        ...e,
        _username: e.encrypted_username ? await decrypt(e.encrypted_username, vaultKey) : "",
        _password: e.encrypted_password ? await decrypt(e.encrypted_password, vaultKey) : "",
        _notes: e.encrypted_notes ? await decrypt(e.encrypted_notes, vaultKey) : "",
      })));
      setEntries(decrypted);
    } finally {
      setLoading(false);
    }
  }, [vaultKey]);

  useEffect(() => { loadEntries(); }, [loadEntries]);

  async function handleDelete(id: string) {
    if (!confirm("Delete this entry?")) return;
    await api.vault.delete(id);
    setEntries(es => es.filter(e => e.id !== id));
  }

  async function loadDevices() {
    const d = await api.webauthn.listDevices();
    setDevices(d);
  }

  async function addBiometric() {
    const name = prompt("Name this device (e.g. My MacBook):");
    if (!name) return;
    try {
      await registerBiometric(name);
      await loadDevices();
      alert("✅ Biometric registered successfully!");
    } catch (err: any) {
      alert("Failed: " + err.message);
    }
  }

  async function removeDevice(id: string) {
    if (!confirm("Remove this device?")) return;
    await api.webauthn.removeDevice(id);
    await loadDevices();
  }

  const filtered = entries.filter(e =>
    e.site_name.toLowerCase().includes(search.toLowerCase()) ||
    e._username?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={styles.appWrap}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <span style={{ fontSize: 24 }}>🔐</span>
          <span style={styles.headerTitle}>Vault</span>
          <span style={styles.headerUser}>{username}</span>
        </div>
        <div style={styles.headerRight}>
          <button style={styles.iconBtn} onClick={() => { setShowSettings(true); loadDevices(); }} title="Settings">⚙️</button>
          <button style={styles.iconBtn} onClick={logout} title="Lock">🔒</button>
        </div>
      </div>

      {/* Search + Add */}
      <div style={styles.toolbar}>
        <input style={{ ...styles.input, flex: 1, marginBottom: 0 }}
          placeholder="🔍  Search entries…" value={search}
          onChange={e => setSearch(e.target.value)} />
        <button style={styles.btn} onClick={() => { setEditEntry(null); setShowForm(true); }}>
          + Add Entry
        </button>
      </div>

      {/* Entries */}
      <div style={styles.entriesGrid}>
        {loading && <p style={styles.empty}>Decrypting vault…</p>}
        {!loading && filtered.length === 0 && (
          <p style={styles.empty}>
            {search ? "No entries match your search." : "No entries yet. Add your first password!"}
          </p>
        )}
        {filtered.map(entry => (
          <EntryCard key={entry.id} entry={entry}
            onEdit={() => { setEditEntry(entry); setShowForm(true); }}
            onDelete={() => handleDelete(entry.id)} />
        ))}
      </div>

      {/* Entry Form Modal */}
      {showForm && vaultKey && (
        <EntryForm
          entry={editEntry}
          vaultKey={vaultKey}
          onSave={() => { setShowForm(false); loadEntries(); }}
          onCancel={() => setShowForm(false)}
        />
      )}

      {/* Settings Modal */}
      {showSettings && (
        <div style={styles.modal}>
          <div style={styles.modalCard}>
            <h2 style={styles.modalTitle}>⚙️ Settings</h2>
            <h3 style={{ color: "var(--text)", marginBottom: 8 }}>Registered Devices</h3>
            <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 12 }}>
              Add Touch ID / Face ID for quick access on this device.
            </p>
            {devices.map(d => (
              <div key={d.id} style={styles.deviceRow}>
                <span>📱 {d.device_name || "Unknown device"}</span>
                <span style={{ color: "var(--muted)", fontSize: 12 }}>
                  {d.last_used ? `Last used: ${new Date(d.last_used).toLocaleDateString()}` : "Never used"}
                </span>
                <button style={styles.cancelBtn} onClick={() => removeDevice(d.id)}>Remove</button>
              </div>
            ))}
            {devices.length === 0 && <p style={{ color: "var(--muted)" }}>No devices registered.</p>}
            <button style={{ ...styles.btn, marginTop: 12 }} onClick={addBiometric}>
              👆 Register This Device
            </button>
            <button style={{ ...styles.cancelBtn, marginTop: 8 }} onClick={() => setShowSettings(false)}>
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

function Inner() {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <VaultApp /> : <AuthScreen />;
}

export default function App() {
  return (
    <AuthProvider>
      <Inner />
    </AuthProvider>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles: Record<string, React.CSSProperties> = {
  authWrap: {
    minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
    background: "var(--bg)", padding: 16,
  },
  authCard: {
    background: "var(--surface)", borderRadius: 16, padding: "40px 36px",
    width: "100%", maxWidth: 400, boxShadow: "0 8px 40px rgba(0,0,0,0.25)",
    border: "1px solid var(--border)",
  },
  authLogo: { fontSize: 48, textAlign: "center", marginBottom: 8 },
  authTitle: { color: "var(--text)", fontSize: 24, fontWeight: 700, textAlign: "center", margin: 0 },
  authSub: { color: "var(--muted)", fontSize: 14, textAlign: "center", marginTop: 6, marginBottom: 24 },
  tabRow: { display: "flex", gap: 8, marginBottom: 20 },
  tab: {
    flex: 1, padding: "8px 0", border: "1px solid var(--border)", borderRadius: 8,
    background: "transparent", color: "var(--muted)", cursor: "pointer", fontSize: 14,
  },
  tabActive: { background: "var(--accent)", color: "#fff", borderColor: "var(--accent)", fontWeight: 600 },
  form: { display: "flex", flexDirection: "column", gap: 12 },
  input: {
    padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)",
    background: "var(--input-bg)", color: "var(--text)", fontSize: 14,
    outline: "none", width: "100%", boxSizing: "border-box", marginBottom: 0,
  },
  btn: {
    padding: "10px 18px", borderRadius: 8, border: "none",
    background: "var(--accent)", color: "#fff", fontWeight: 600,
    cursor: "pointer", fontSize: 14, whiteSpace: "nowrap",
  },
  cancelBtn: {
    padding: "10px 18px", borderRadius: 8, border: "1px solid var(--border)",
    background: "transparent", color: "var(--muted)", cursor: "pointer", fontSize: 14,
  },
  biometricBtn: {
    display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
    width: "100%", marginTop: 12, padding: "10px 0", borderRadius: 8,
    border: "1px solid var(--border)", background: "transparent",
    color: "var(--text)", cursor: "pointer", fontSize: 14,
  },
  error: { color: "#f87171", fontSize: 13, margin: 0 },
  zeroKnowledge: {
    fontSize: 12, color: "var(--muted)", textAlign: "center",
    marginTop: 20, lineHeight: 1.5,
  },
  appWrap: { minHeight: "100vh", background: "var(--bg)", display: "flex", flexDirection: "column" },
  header: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "14px 20px", borderBottom: "1px solid var(--border)",
    background: "var(--surface)", position: "sticky", top: 0, zIndex: 10,
  },
  headerLeft: { display: "flex", alignItems: "center", gap: 10 },
  headerTitle: { color: "var(--text)", fontWeight: 700, fontSize: 18 },
  headerUser: {
    color: "var(--muted)", fontSize: 13, background: "var(--border)",
    padding: "2px 8px", borderRadius: 20,
  },
  headerRight: { display: "flex", gap: 4 },
  toolbar: {
    display: "flex", gap: 10, padding: "16px 20px",
    borderBottom: "1px solid var(--border)", alignItems: "center",
  },
  entriesGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
    gap: 14, padding: 20,
  },
  empty: { color: "var(--muted)", gridColumn: "1/-1", textAlign: "center", paddingTop: 60 },
  card: {
    background: "var(--surface)", borderRadius: 12, padding: 16,
    border: "1px solid var(--border)", display: "flex", flexDirection: "column", gap: 8,
  },
  cardHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start" },
  cardSite: { display: "flex", gap: 10, alignItems: "center" },
  cardIcon: { fontSize: 24 },
  cardName: { color: "var(--text)", fontWeight: 600, fontSize: 15 },
  cardUrl: { color: "var(--accent)", fontSize: 12, textDecoration: "none" },
  cardActions: { display: "flex", gap: 2 },
  fieldRow: { display: "flex", alignItems: "center", gap: 8, minHeight: 28 },
  fieldLabel: { color: "var(--muted)", fontSize: 12, width: 68, flexShrink: 0 },
  fieldValue: { color: "var(--text)", fontSize: 13, flex: 1, fontFamily: "monospace", wordBreak: "break-all" },
  copyBtn: {
    padding: "2px 6px", borderRadius: 6, border: "1px solid var(--border)",
    background: "transparent", cursor: "pointer", fontSize: 14,
  },
  iconBtn: {
    padding: "4px 8px", borderRadius: 6, border: "none",
    background: "transparent", cursor: "pointer", fontSize: 16,
  },
  ssoTag: {
    display: "inline-block", fontSize: 12, color: "var(--muted)",
    border: "1px solid var(--border)", borderRadius: 20, padding: "2px 10px",
  },
  pwRow: { display: "flex", gap: 6, alignItems: "center" },
  genRow: { display: "flex", gap: 8, alignItems: "center" },
  genBtn: {
    padding: "6px 12px", borderRadius: 6, border: "1px solid var(--border)",
    background: "transparent", color: "var(--text)", cursor: "pointer", fontSize: 13, whiteSpace: "nowrap",
  },
  genLen: { color: "var(--muted)", fontSize: 13, width: 24 },
  modal: {
    position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)",
    display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, padding: 16,
  },
  modalCard: {
    background: "var(--surface)", borderRadius: 16, padding: 28,
    width: "100%", maxWidth: 480, maxHeight: "90vh", overflowY: "auto",
    border: "1px solid var(--border)",
  },
  modalTitle: { color: "var(--text)", fontSize: 18, fontWeight: 700, marginBottom: 16 },
  modalActions: { display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 8 },
  deviceRow: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    gap: 8, padding: "8px 0", borderBottom: "1px solid var(--border)",
  },
};
