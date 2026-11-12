// Client-side checks for the New scan form. The server enforces the same bounds
// (timeout_s: integer 5-600) and remains the authority; these give immediate feedback.

export const TIMEOUT_MIN_S = 5;
export const TIMEOUT_MAX_S = 600;

export type TimeoutParse = { ok: true; value: number | undefined } | { ok: false; error: string };

/**
 * Parse the timeout field. A blank field returns `undefined` so the request omits
 * `timeout_s` and the server default applies.
 */
export function parseTimeout(text: string): TimeoutParse {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: true, value: undefined };
  const bounds = `Timeout must be a whole number of seconds from ${TIMEOUT_MIN_S} to ${TIMEOUT_MAX_S}.`;
  if (!/^\d+$/.test(trimmed)) return { ok: false, error: bounds };
  const value = Number(trimmed);
  if (value < TIMEOUT_MIN_S || value > TIMEOUT_MAX_S) return { ok: false, error: bounds };
  return { ok: true, value };
}
