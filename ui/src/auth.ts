import { useSyncExternalStore } from "react";

/**
 * The access token for a server that was started with one.
 *
 * It lives in memory and in sessionStorage, so a reload of the same tab keeps it and closing the
 * tab forgets it. It is never put in localStorage, never in a URL, and never logged.
 */
const STORAGE_KEY = "skillsentry.token";

export interface AuthState {
  /** The token sent with every request, or null. */
  token: string | null;
  /** True once the server has answered 401: the prompt is shown. */
  required: boolean;
  /** Changes whenever the token or the need for one changes, so loaders can run again. */
  version: number;
}

function readStored(): string | null {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY);
  } catch {
    // sessionStorage can be blocked or unavailable; the token then lives in memory only.
    return null;
  }
}

function writeStored(token: string | null): void {
  try {
    if (token === null) window.sessionStorage.removeItem(STORAGE_KEY);
    else window.sessionStorage.setItem(STORAGE_KEY, token);
  } catch {
    // Memory only.
  }
}

let state: AuthState = { token: readStored(), required: false, version: 0 };
const listeners = new Set<() => void>();

function update(next: Partial<AuthState>): void {
  state = { ...state, ...next, version: state.version + 1 };
  listeners.forEach((listener) => listener());
}

export function getAuth(): AuthState {
  return state;
}

export function getToken(): string | null {
  return state.token;
}

/** Remember a token that the server accepted, and let the dashboard load again. */
export function setToken(token: string): void {
  writeStored(token);
  update({ token, required: false });
}

/** The server refused a request: drop a token that did not work and ask for one. */
export function reportUnauthorized(): void {
  if (state.required && state.token === null) return;
  writeStored(null);
  update({ token: null, required: true });
}

/** Forget the token and ask for a new one. */
export function signOut(): void {
  writeStored(null);
  update({ token: null, required: true });
}

/** For tests: back to a clean state without a token. */
export function resetAuthForTests(): void {
  writeStored(null);
  state = { token: null, required: false, version: 0 };
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useAuth(): AuthState {
  return useSyncExternalStore(subscribe, getAuth, getAuth);
}
