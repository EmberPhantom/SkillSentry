import { useState, type FormEvent } from "react";
import { describeError, verifyToken } from "../api";
import { setToken } from "../auth";

/** Shown when the server answers 401: asks for the access token it was started with. */
export function TokenPrompt() {
  const [value, setValue] = useState("");
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const candidate = value.trim();
    if (!candidate) {
      setError("Enter the access token.");
      return;
    }
    setChecking(true);
    setError(null);
    try {
      if (await verifyToken(candidate)) {
        // Clear the field before the token is kept, so it is not left in the page.
        setValue("");
        setToken(candidate);
      } else {
        setError("That token was not accepted. Check it and try again.");
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setChecking(false);
    }
  }

  return (
    <section className="page" aria-labelledby="token-title">
      <h1 id="token-title">Access token needed</h1>
      <p className="muted">
        This server was started with a token. Enter it to use the dashboard. It is kept for this
        browser tab only, and sent only to this server.
      </p>
      <form onSubmit={submit} className="card token-form" aria-busy={checking}>
        <label className="field">
          <span>Access token</span>
          <input
            type="password"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            autoFocus
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "token-error" : undefined}
          />
        </label>
        {error ? (
          <p id="token-error" role="alert" className="error-text">
            {error}
          </p>
        ) : null}
        <button type="submit" disabled={checking}>
          {checking ? "Checking…" : "Continue"}
        </button>
      </form>
    </section>
  );
}
