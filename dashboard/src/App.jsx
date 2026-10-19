import { useCallback, useEffect, useMemo, useState } from "react";

const DEFAULT_API_URL = "http://localhost:8000";
const initialRequest = {
  resource_name: "mock-backend",
  port: "5678",
  protocol: "tcp",
};

function getApiOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Enter a valid backend API origin.");
  }

  const localHosts = new Set(["localhost", "127.0.0.1", "::1"]);
  if (
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    (parsed.protocol !== "https:" &&
      !(parsed.protocol === "http:" && localHosts.has(parsed.hostname)))
  ) {
    throw new Error(
      "Use an HTTPS API origin. HTTP is allowed only for localhost development.",
    );
  }
  return parsed.origin;
}

function formatError(error, fallback) {
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

async function requestJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw new Error(
      "Could not reach the API. Check the API address, backend status, and browser CORS configuration.",
    );
  }

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // Keep the HTTP status message when the response has no JSON body.
    }
    throw new Error(detail);
  }

  if (response.status === 204) return null;
  return response.json();
}

function Icon({ name, size = 18 }) {
  const paths = {
    shield: (
      <path d="M12 3 20 6v5c0 5.2-3.4 8.6-8 10-4.6-1.4-8-4.8-8-10V6l8-3Z" />
    ),
    refresh: (
      <>
        <path d="M20 7v5h-5" />
        <path d="M4.9 9A7.5 7.5 0 0 1 18 6.4L20 12M4 17v-5h5" />
        <path d="M19.1 15A7.5 7.5 0 0 1 6 17.6L4 12" />
      </>
    ),
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    network: (
      <>
        <rect x="9" y="3" width="6" height="6" rx="1" />
        <rect x="3" y="15" width="6" height="6" rx="1" />
        <rect x="15" y="15" width="6" height="6" rx="1" />
        <path d="M12 9v3m-6 3v-3h12v3" />
      </>
    ),
  };

  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {paths[name]}
    </svg>
  );
}

export default function App() {
  const [apiUrl, setApiUrl] = useState(DEFAULT_API_URL);
  const [token, setToken] = useState("");
  const [request, setRequest] = useState(initialRequest);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [revokingId, setRevokingId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const normalizedApiUrl = useMemo(() => apiUrl.trim().replace(/\/+$/, ""), [apiUrl]);
  const authenticated = token.trim().length > 0;

  const loadFlows = useCallback(async () => {
    if (!authenticated) {
      setFlows([]);
      setError("Enter a Keycloak access token to view authorized flows.");
      return false;
    }
    if (!normalizedApiUrl) {
      setError("Enter the backend API address.");
      return false;
    }

    setLoading(true);
    setError("");
    setNotice("");
    try {
      const origin = getApiOrigin(normalizedApiUrl);
      const result = await requestJson(`${origin}/flows`, {
        headers: { Authorization: `Bearer ${token.trim()}` },
      });
      if (!Array.isArray(result)) throw new Error("The API returned an invalid flow list.");
      setFlows(result);
      setLastUpdated(new Date());
      return true;
    } catch (loadError) {
      setError(formatError(loadError, "Could not load flows."));
      return false;
    } finally {
      setLoading(false);
    }
  }, [authenticated, normalizedApiUrl, token]);

  useEffect(() => {
    setFlows([]);
    setError("");
    setNotice("");
    setLastUpdated(null);
  }, [normalizedApiUrl, token]);

  async function authorizeFlow(event) {
    event.preventDefault();
    if (!authenticated) {
      setError("Enter a Keycloak access token before requesting access.");
      return;
    }

    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      const origin = getApiOrigin(normalizedApiUrl);
      await requestJson(`${origin}/flows/authorize`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token.trim()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          resource_name: request.resource_name.trim(),
          port: Number(request.port),
          protocol: request.protocol,
        }),
      });
      const refreshed = await loadFlows();
      setNotice(
        refreshed
          ? `Access approved for ${request.resource_name.trim()}.`
          : `Access was approved for ${request.resource_name.trim()}, but the flow list could not be refreshed.`,
      );
    } catch (submitError) {
      setError(formatError(submitError, "Could not authorize this flow."));
    } finally {
      setSubmitting(false);
    }
  }

  async function revokeFlow(flow) {
    setRevokingId(flow.flow_id);
    setError("");
    setNotice("");
    try {
      await requestJson(
        `${getApiOrigin(normalizedApiUrl)}/flows/${encodeURIComponent(flow.flow_id)}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token.trim()}` },
        },
      );
      setFlows((current) =>
        current.filter((item) => item.flow_id !== flow.flow_id),
      );
      setNotice(`Flow to ${flow.destination_ipv4}:${flow.destination_port} revoked.`);
    } catch (revokeError) {
      setError(formatError(revokeError, "Could not revoke this flow."));
    } finally {
      setRevokingId("");
    }
  }

  function updateRequest(field, value) {
    setRequest((current) => ({ ...current, [field]: value }));
  }

  return (
    <div className="app-shell">
      <style>{styles}</style>
      <aside className="sidebar">
        <a className="brand" href="#overview" aria-label="Gateway home">
          <span className="brand-mark">
            <Icon name="shield" size={21} />
          </span>
          <span className="brand-name">
            <strong>Sentinel</strong>
            <small>ZERO-TRUST GATEWAY</small>
          </span>
        </a>

        <div className="nav-label">CONTROL PLANE</div>
        <a className="nav-item active" href="#overview">
          <Icon name="network" size={17} />
          <span>Access overview</span>
        </a>

        <div className="sidebar-bottom">
          <div className="security-note">
            <span className="security-dot" />
            <span>Policy enforcement active</span>
          </div>
          <div className="sidebar-caption">FASTAPI · OPA · eBPF</div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Gateway</span>
            <span className="crumb-divider">/</span>
            <strong>Access overview</strong>
          </div>
          <div className="topbar-status">
            <span className={`status-dot ${authenticated ? "ready" : ""}`} />
            {authenticated ? "Token supplied" : "Authentication required"}
          </div>
        </header>

        <div className="page">
          <section className="page-heading">
            <div>
              <div className="eyebrow">NETWORK ACCESS CONTROL</div>
              <h1>Access overview</h1>
              <p className="subtitle">
                Request least-privilege access and manage active network flows.
              </p>
            </div>
            <button
              className="button button-secondary refresh-button"
              type="button"
              onClick={loadFlows}
              disabled={loading || !authenticated}
            >
              <Icon name="refresh" size={16} />
              {loading ? "Refreshing" : "Refresh"}
            </button>
          </section>

          <section className="connection-card">
            <div className="connection-icon">
              <Icon name="shield" size={19} />
            </div>
            <div className="connection-copy">
              <strong>Secure API connection</strong>
              <span>Provide a Keycloak bearer token to manage your access.</span>
            </div>
            <label className="api-field">
              <span>API ORIGIN · HTTPS REQUIRED OUTSIDE LOCALHOST</span>
              <input
                aria-label="Backend API address"
                value={apiUrl}
                onChange={(event) => setApiUrl(event.target.value)}
                placeholder="http://localhost:8000"
                inputMode="url"
              />
            </label>
            <label className="token-field">
              <span>ACCESS TOKEN</span>
              <input
                aria-label="Keycloak access token"
                type="password"
                autoComplete="off"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                placeholder="Paste your Keycloak access token"
              />
            </label>
            <button
              className="button button-secondary connect-button"
              type="button"
              onClick={loadFlows}
              disabled={loading || !authenticated}
            >
              {loading ? "Loading…" : "Load flows"}
              {!loading && <Icon name="arrow" size={15} />}
            </button>
          </section>

          <div className="summary-grid">
            <article className="summary-card">
              <div className="summary-top">
                <span>ACTIVE FLOWS</span>
                <span className="summary-icon blue">
                  <Icon name="network" size={17} />
                </span>
              </div>
              <strong className="summary-value">{flows.length}</strong>
              <span className="summary-foot">Authorized kernel map entries</span>
            </article>
            <article className="summary-card">
              <div className="summary-top">
                <span>POLICY ENGINE</span>
                <span className="summary-icon green">
                  <Icon name="shield" size={17} />
                </span>
              </div>
              <strong className="summary-state">OPA</strong>
              <span className="summary-foot">Every request evaluated before access</span>
            </article>
            <article className="summary-card">
              <div className="summary-top">
                <span>LAST SYNC</span>
                <span className="summary-icon amber">
                  <Icon name="refresh" size={17} />
                </span>
              </div>
              <strong className="summary-state">
                {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"}
              </strong>
              <span className="summary-foot">
                {lastUpdated ? "Flow list refreshed" : "No flow data loaded"}
              </span>
            </article>
          </div>

          {error && (
            <div className="alert alert-error" role="alert">
              <span className="alert-symbol">!</span>
              <div>
                <strong>Request could not be completed</strong>
                <p>{error}</p>
                {error.includes("WireGuard client address") && (
                  <p>
                    The backend currently expects a validated token claim named{" "}
                    <code>wg_client_ipv4</code>.
                  </p>
                )}
              </div>
              <button
                className="alert-dismiss"
                type="button"
                aria-label="Dismiss error"
                onClick={() => setError("")}
              >
                <Icon name="close" size={16} />
              </button>
            </div>
          )}

          {notice && (
            <div className="alert alert-success" role="status">
              <span className="success-check">✓</span>
              <p>{notice}</p>
              <button
                className="alert-dismiss"
                type="button"
                aria-label="Dismiss message"
                onClick={() => setNotice("")}
              >
                <Icon name="close" size={16} />
              </button>
            </div>
          )}

          <div className="content-grid">
            <section className="panel flow-panel">
              <div className="panel-heading">
                <div>
                  <h2>Authorized flows</h2>
                  <p>Active client-to-service permissions</p>
                </div>
                <span className="count-pill">{flows.length} total</span>
              </div>

              {!authenticated ? (
                <div className="empty-state">
                  <div className="empty-icon">
                    <Icon name="shield" size={22} />
                  </div>
                  <strong>Authenticate to view flows</strong>
                  <p>Paste a valid Keycloak access token above to continue.</p>
                </div>
              ) : loading && flows.length === 0 ? (
                <div className="empty-state">
                  <span className="spinner" />
                  <strong>Loading authorized flows</strong>
                  <p>Fetching the current flow list from the gateway.</p>
                </div>
              ) : flows.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon muted">
                    <Icon name="network" size={22} />
                  </div>
                  <strong>No active flows</strong>
                  <p>Request service access to create your first authorized flow.</p>
                </div>
              ) : (
                <div className="flow-list">
                  {flows.map((flow) => (
                    <article className="flow-row" key={flow.flow_id}>
                      <div className="flow-indicator">
                        <span />
                      </div>
                      <div className="flow-details">
                        <div className="flow-route">
                          <span className="flow-address">{flow.client_ipv4}</span>
                          <span className="route-line" />
                          <span className="flow-address destination">
                            {flow.destination_ipv4}:{flow.destination_port}
                          </span>
                        </div>
                        <div className="flow-meta">
                          <span className="protocol-tag">{flow.protocol}</span>
                          <span className="flow-id">{flow.flow_id}</span>
                        </div>
                      </div>
                      <span className="active-badge">ACTIVE</span>
                      <button
                        className="revoke-button"
                        type="button"
                        onClick={() => revokeFlow(flow)}
                        disabled={revokingId === flow.flow_id}
                        aria-label={`Revoke flow to ${flow.destination_ipv4}:${flow.destination_port}`}
                      >
                        <Icon name="close" size={16} />
                        <span>
                          {revokingId === flow.flow_id ? "Revoking…" : "Revoke"}
                        </span>
                      </button>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="panel request-panel">
              <div className="panel-heading">
                <div>
                  <h2>Request access</h2>
                  <p>Specify the service you need to reach</p>
                </div>
                <span className="step-label">01 / 01</span>
              </div>

              <form className="access-form" onSubmit={authorizeFlow}>
                <label className="form-field">
                  <span>Service name</span>
                  <input
                    required
                    maxLength={253}
                    value={request.resource_name}
                    onChange={(event) =>
                      updateRequest("resource_name", event.target.value)
                    }
                    placeholder="e.g. mock-backend"
                  />
                  <small>Must match a service defined in gateway policy.</small>
                </label>

                <div className="form-row">
                  <label className="form-field">
                    <span>Destination port</span>
                    <input
                      required
                      type="number"
                      min="1"
                      max="65535"
                      value={request.port}
                      onChange={(event) => updateRequest("port", event.target.value)}
                    />
                  </label>
                  <label className="form-field">
                    <span>Protocol</span>
                    <select
                      value={request.protocol}
                      onChange={(event) =>
                        updateRequest("protocol", event.target.value)
                      }
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </label>
                </div>

                <div className="policy-note">
                  <Icon name="shield" size={16} />
                  <span>OPA will evaluate your role before the flow is installed.</span>
                </div>

                <button
                  className="button button-primary submit-button"
                  type="submit"
                  disabled={submitting || !authenticated}
                >
                  {submitting ? "Evaluating policy…" : "Request access"}
                  {!submitting && <Icon name="arrow" size={16} />}
                </button>
                {!authenticated && (
                  <div className="form-hint">
                    Add an access token above to enable requests.
                  </div>
                )}
              </form>
            </section>
          </div>

          <footer className="page-footer">
            <span>Zero-Trust eBPF Gateway</span>
            <span>Access is verified per flow · Revocation removes the map entry</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

const styles = `
  :root { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #182329; background: #f5f7f6; font-synthesis: none; text-rendering: optimizeLegibility; }
  * { box-sizing: border-box; }
  body { margin: 0; min-width: 320px; min-height: 100vh; }
  button, input, select { font: inherit; }
  button { cursor: pointer; }
  button:disabled { cursor: not-allowed; opacity: .58; }
  .app-shell { min-height: 100vh; }
  .sidebar { width: 238px; background: #10221f; color: #d5e1dc; position: fixed; inset: 0 auto 0 0; display: flex; flex-direction: column; padding: 27px 17px 19px; z-index: 2; }
  .brand { display: flex; align-items: center; gap: 11px; text-decoration: none; color: inherit; margin: 0 4px 57px; }
  .brand-mark { width: 38px; height: 38px; border-radius: 11px; background: #2f9878; color: white; display: grid; place-items: center; }
  .brand-name { display: flex; flex-direction: column; gap: 3px; }
  .brand-name strong { font-size: 17px; color: #f5faf7; letter-spacing: -.4px; }
  .brand-name small { color: #86a198; font: 9px ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: 1.15px; }
  .nav-label { padding: 0 11px; color: #779087; font: 9px ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: 1.25px; margin-bottom: 11px; }
  .nav-item { height: 42px; display: flex; align-items: center; gap: 11px; padding: 0 11px; text-decoration: none; color: #a8bdb5; font-size: 12px; border-radius: 7px; }
  .nav-item.active { color: white; background: #203a33; box-shadow: inset 2px 0 #5cc49f; }
  .sidebar-bottom { margin-top: auto; border-top: 1px solid #294039; padding: 17px 6px 0; }
  .security-note { display: flex; align-items: center; gap: 8px; font-size: 10px; color: #b1c4bc; }
  .security-dot, .status-dot { width: 7px; height: 7px; border-radius: 50%; background: #62c69c; box-shadow: 0 0 0 3px #62c69c1d; }
  .sidebar-caption { margin: 15px 0 0 15px; color: #71877f; font: 9px ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .65px; }
  .main-content { min-height: 100vh; margin-left: 238px; }
  .topbar { height: 63px; padding: 0 40px; background: #fff; border-bottom: 1px solid #e8eeeb; display: flex; justify-content: space-between; align-items: center; }
  .breadcrumbs { display: flex; gap: 10px; color: #87948f; font-size: 11px; }
  .breadcrumbs strong { font-weight: 600; color: #35443f; }
  .crumb-divider { color: #c4ceca; }
  .topbar-status { display: flex; align-items: center; gap: 8px; font-size: 10px; color: #718079; }
  .status-dot { background: #bbc5c1; box-shadow: none; }
  .status-dot.ready { background: #3ca97f; box-shadow: 0 0 0 3px #3ca97f1c; }
  .page { max-width: 1320px; padding: 37px 40px 22px; margin: 0 auto; }
  .page-heading { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 25px; }
  .eyebrow { font: 9px ui-monospace, SFMono-Regular, Consolas, monospace; color: #3c9a78; letter-spacing: 1.5px; margin-bottom: 9px; }
  h1 { margin: 0; font-size: 25px; letter-spacing: -.8px; color: #182622; }
  .subtitle { margin: 7px 0 0; font-size: 12px; color: #7b8983; }
  .button { border: 0; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-weight: 600; transition: background .15s ease, transform .15s ease; }
  .button:not(:disabled):active { transform: translateY(1px); }
  .button-secondary { background: white; color: #384c44; border: 1px solid #dce5e0; }
  .button-secondary:hover:not(:disabled) { background: #f5f9f7; }
  .refresh-button { height: 34px; padding: 0 12px; font-size: 10px; }
  .connection-card { display: grid; grid-template-columns: 36px minmax(180px, 1fr) minmax(140px, .72fr) minmax(190px, 1.1fr) auto; align-items: center; gap: 14px; background: #fff; border: 1px solid #e4ebe7; border-radius: 9px; padding: 15px 17px; box-shadow: 0 2px 5px #1d34220a; margin-bottom: 16px; }
  .connection-icon { width: 35px; height: 35px; background: #e8f5ef; color: #329271; border-radius: 8px; display: grid; place-items: center; }
  .connection-copy { display: flex; flex-direction: column; gap: 4px; }
  .connection-copy strong { font-size: 11px; color: #26362f; }
  .connection-copy span { font-size: 9px; color: #84918b; }
  .api-field, .token-field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
  .api-field > span, .token-field > span { color: #84928b; font: 8px ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .85px; }
  .api-field input, .token-field input { min-width: 0; width: 100%; height: 31px; background: #fbfcfb; border: 1px solid #e3eae6; border-radius: 5px; padding: 0 9px; color: #3d5048; font-size: 10px; outline: none; }
  .api-field input:focus, .token-field input:focus, .form-field input:focus, .form-field select:focus { border-color: #64b995; box-shadow: 0 0 0 3px #52ad881a; }
  .connect-button { height: 32px; margin-top: 14px; padding: 0 10px; white-space: nowrap; font-size: 9px; }
  .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 19px; }
  .summary-card { background: white; border: 1px solid #e5ebe8; border-radius: 8px; padding: 14px 16px 13px; min-height: 111px; }
  .summary-top { display: flex; align-items: center; justify-content: space-between; color: #8a9690; font: 8px ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .9px; }
  .summary-icon { width: 28px; height: 28px; border-radius: 7px; display: grid; place-items: center; }
  .summary-icon.blue { color: #5b84bd; background: #edf3fa; }
  .summary-icon.green { color: #3f9b78; background: #eaf5ef; }
  .summary-icon.amber { color: #bd9650; background: #faf4e9; }
  .summary-value, .summary-state { display: block; margin-top: 3px; font-size: 21px; letter-spacing: -.5px; color: #263830; }
  .summary-state { font-size: 15px; margin-top: 7px; }
  .summary-foot { display: block; margin-top: 3px; font-size: 9px; color: #929e98; }
  .alert { display: flex; align-items: flex-start; gap: 10px; padding: 11px 13px; border-radius: 7px; margin-bottom: 14px; font-size: 10px; }
  .alert-error { border: 1px solid #f1d0ca; background: #fff8f6; color: #943f33; }
  .alert-success { border: 1px solid #cfe8d9; background: #f4fbf6; color: #327052; align-items: center; }
  .alert-symbol, .success-check { flex: 0 0 18px; width: 18px; height: 18px; display: grid; place-items: center; border-radius: 50%; font-size: 11px; font-weight: 700; }
  .alert-symbol { color: white; background: #c96b5d; }
  .success-check { color: white; background: #48a87c; }
  .alert strong { font-size: 10px; }
  .alert p { margin: 3px 0 0; line-height: 1.5; }
  .alert code { font: 10px ui-monospace, SFMono-Regular, Consolas, monospace; }
  .alert-dismiss { border: 0; background: transparent; color: currentColor; margin-left: auto; padding: 1px; display: grid; }
  .content-grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(280px, .85fr); gap: 16px; align-items: start; }
  .panel { background: white; border: 1px solid #e4ebe7; border-radius: 9px; box-shadow: 0 2px 5px #1d342208; overflow: hidden; }
  .panel-heading { display: flex; justify-content: space-between; align-items: center; min-height: 70px; padding: 15px 17px; border-bottom: 1px solid #edf1ef; }
  .panel-heading h2 { font-size: 13px; color: #273630; letter-spacing: -.2px; margin: 0; }
  .panel-heading p { font-size: 9px; color: #8a9690; margin: 5px 0 0; }
  .count-pill, .step-label { color: #648176; background: #eef5f1; border-radius: 4px; padding: 5px 7px; font: 8px ui-monospace, SFMono-Regular, Consolas, monospace; }
  .step-label { background: none; color: #9aa6a0; padding: 0; }
  .empty-state { min-height: 242px; padding: 37px 20px; display: flex; align-items: center; flex-direction: column; justify-content: center; text-align: center; }
  .empty-icon { color: #58a987; background: #edf7f1; width: 43px; height: 43px; display: grid; place-items: center; border-radius: 50%; margin-bottom: 12px; }
  .empty-icon.muted { color: #98a69f; background: #f2f5f3; }
  .empty-state strong { color: #37463f; font-size: 11px; }
  .empty-state p { color: #929d97; max-width: 250px; font-size: 9px; line-height: 1.6; margin: 6px 0 0; }
  .spinner { width: 23px; height: 23px; border: 2px solid #e1eee7; border-top-color: #48a980; border-radius: 50%; animation: spin .8s linear infinite; margin-bottom: 14px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .flow-list { padding: 0 16px; }
  .flow-row { min-height: 72px; display: flex; align-items: center; gap: 11px; border-bottom: 1px solid #edf1ef; }
  .flow-row:last-child { border-bottom: 0; }
  .flow-indicator { width: 26px; height: 26px; flex: 0 0 26px; display: grid; place-items: center; background: #eff7f2; border-radius: 7px; }
  .flow-indicator span { width: 7px; height: 7px; border-radius: 50%; background: #51ac80; box-shadow: 0 0 0 3px #51ac801e; }
  .flow-details { flex: 1; min-width: 0; }
  .flow-route { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .flow-address { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #3c4e46; font: 10px ui-monospace, SFMono-Regular, Consolas, monospace; }
  .flow-address.destination { color: #253b31; }
  .route-line { height: 1px; width: 18px; background: #a6c5b5; flex: 0 0 18px; position: relative; }
  .route-line:after { content: ''; position: absolute; right: 0; top: -2px; width: 4px; height: 4px; border-right: 1px solid #78a68d; border-top: 1px solid #78a68d; transform: rotate(45deg); }
  .flow-meta { display: flex; align-items: center; gap: 7px; margin-top: 6px; }
  .protocol-tag { color: #597969; text-transform: uppercase; background: #f0f5f2; border-radius: 3px; padding: 2px 5px; font: 8px ui-monospace, SFMono-Regular, Consolas, monospace; }
  .flow-id { color: #9aa49f; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 8px ui-monospace, SFMono-Regular, Consolas, monospace; }
  .active-badge { flex: 0 0 auto; color: #398565; background: #eef8f2; padding: 4px 6px; border-radius: 3px; font: 8px ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .3px; }
  .revoke-button { flex: 0 0 auto; border: 1px solid #eddeda; background: white; color: #ad6358; height: 28px; padding: 0 7px; border-radius: 5px; display: flex; align-items: center; gap: 3px; font-size: 9px; }
  .revoke-button:hover:not(:disabled) { background: #fff7f5; border-color: #dfb8b0; }
  .access-form { padding: 17px; }
  .form-field { min-width: 0; display: flex; flex-direction: column; gap: 7px; }
  .form-field > span { color: #58675f; font-size: 10px; font-weight: 600; }
  .form-field input, .form-field select { height: 36px; width: 100%; padding: 0 10px; background: white; border: 1px solid #dfe7e2; border-radius: 5px; color: #34443c; font-size: 10px; outline: none; }
  .form-field small { color: #98a39d; font-size: 8px; margin-top: -1px; }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px; }
  .policy-note { display: flex; align-items: center; gap: 8px; padding: 10px; margin-top: 18px; border: 1px solid #e2eee7; border-radius: 5px; color: #54836c; background: #f7fbf8; font-size: 9px; line-height: 1.45; }
  .policy-note svg { flex: 0 0 auto; }
  .button-primary { height: 37px; width: 100%; background: #278566; color: white; font-size: 10px; margin-top: 14px; }
  .button-primary:hover:not(:disabled) { background: #1f7257; }
  .form-hint { text-align: center; color: #99a39e; font-size: 8px; margin-top: 9px; }
  .page-footer { margin-top: 19px; display: flex; justify-content: space-between; color: #a0aaa5; font-size: 8px; }
  @media (max-width: 1080px) { .sidebar { width: 205px; } .main-content { margin-left: 205px; } .page { padding-left: 25px; padding-right: 25px; } .topbar { padding-left: 25px; padding-right: 25px; } .connection-card { grid-template-columns: 34px 1fr 1fr; } .connection-copy { grid-column: 2 / 4; grid-row: 1; } .api-field { grid-column: 1 / 2; } .token-field { grid-column: 2 / 4; } .connect-button { grid-column: 3; grid-row: 3; justify-self: end; } }
  @media (max-width: 760px) { .sidebar { width: 58px; padding: 19px 9px; align-items: center; } .brand { margin: 0 0 42px; } .brand-name, .nav-label, .nav-item span, .sidebar-bottom { display: none; } .nav-item { width: 40px; justify-content: center; padding: 0; } .main-content { margin-left: 58px; } .topbar { height: 54px; padding: 0 16px; } .page { padding: 25px 15px 18px; } .page-heading { align-items: flex-start; gap: 12px; } h1 { font-size: 21px; } .subtitle { max-width: 250px; line-height: 1.5; } .summary-grid { gap: 8px; } .summary-card { padding: 11px; min-height: 104px; } .summary-top { font-size: 7px; } .summary-icon { width: 24px; height: 24px; } .summary-foot { line-height: 1.4; } .content-grid { grid-template-columns: 1fr; } .connection-card { grid-template-columns: 30px 1fr; gap: 10px; } .connection-copy { grid-column: 2; grid-row: 1; } .api-field { grid-column: 1 / 3; } .token-field { grid-column: 1 / 3; } .connect-button { grid-column: 1 / 3; grid-row: auto; justify-self: stretch; margin-top: 0; } .flow-row { gap: 7px; } .flow-id { max-width: 115px; } .active-badge { display: none; } .revoke-button { padding: 0 5px; } .page-footer { gap: 8px; line-height: 1.5; } .page-footer span:last-child { text-align: right; } }
  @media (max-width: 430px) { .topbar-status { font-size: 0; gap: 0; } .topbar-status .status-dot { width: 8px; height: 8px; } .refresh-button { padding: 0 8px; } .summary-grid { grid-template-columns: 1fr 1fr; } .summary-card:last-child { grid-column: 1 / 3; } .flow-address { font-size: 8px; } .route-line { width: 10px; flex-basis: 10px; } .flow-id { max-width: 85px; } .revoke-button span { display: none; } }
`;
