import { createContext, useContext, useState, useCallback, ReactNode } from "react";
import { deriveKey } from "../utils/crypto";
import { api } from "../api/client";

interface AuthCtx {
  token: string | null;
  username: string | null;
  vaultKey: CryptoKey | null;
  salt: string;
  login: (username: string, password: string) => Promise<void>;
  loginWithToken: (token: string, username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const Ctx = createContext<AuthCtx | null>(null);

// Salt is derived from username — constant per user, never stored on server
function userSalt(username: string) {
  return `vault-salt-${username}-v1`;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(localStorage.getItem("vault_token"));
  const [username, setUsername] = useState<string | null>(localStorage.getItem("vault_username"));
  const [vaultKey, setVaultKey] = useState<CryptoKey | null>(null);
  const [salt] = useState("");

  const loginWithToken = useCallback(async (tok: string, user: string, password: string) => {
    localStorage.setItem("vault_token", tok);
    localStorage.setItem("vault_username", user);
    setToken(tok);
    setUsername(user);
    // Derive encryption key from master password — never sent to server
    const key = await deriveKey(password, userSalt(user));
    setVaultKey(key);
  }, []);

  const login = useCallback(async (user: string, password: string) => {
    const data = await api.auth.login(user, password);
    await loginWithToken(data.token, data.username, password);
  }, [loginWithToken]);

  const logout = useCallback(() => {
    localStorage.removeItem("vault_token");
    localStorage.removeItem("vault_username");
    setToken(null);
    setUsername(null);
    setVaultKey(null);
  }, []);

  return (
    <Ctx.Provider value={{
      token, username, vaultKey, salt,
      login, loginWithToken, logout,
      isAuthenticated: !!token && !!vaultKey
    }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
