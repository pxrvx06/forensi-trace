import React, { useEffect, useState } from 'react';
import { downloadActivityReportPdf } from '../api/client';

function tokenizeJson(value) {
  const formatted = JSON.stringify(value ?? {}, null, 2);
  const tokens = [];
  const regex =
    /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g;

  let lastIndex = 0;
  let match;
  let keyCounter = 0;

  while ((match = regex.exec(formatted)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({
        id: `p-${keyCounter++}`,
        type: 'punct',
        text: formatted.slice(lastIndex, match.index),
      });
    }

    const token = match[0];
    let type = 'number';
    if (token.startsWith('"')) {
      type = match[2] ? 'key' : 'string';
    } else if (token === 'true' || token === 'false') {
      type = 'boolean';
    } else if (token === 'null') {
      type = 'null';
    }

    tokens.push({ id: `t-${keyCounter++}`, type, text: token });
    lastIndex = regex.lastIndex;
  }

  if (lastIndex < formatted.length) {
    tokens.push({
      id: `p-${keyCounter++}`,
      type: 'punct',
      text: formatted.slice(lastIndex),
    });
  }

  return tokens;
}

export function JsonHighlight({ data, testId }) {
  const tokens = tokenizeJson(data);
  return (
    <pre className="json-highlight" data-testid={testId}>
      <code>
        {tokens.map((tok) => (
          <span key={tok.id} className={`json-${tok.type}`}>
            {tok.text}
          </span>
        ))}
      </code>
    </pre>
  );
}

function extractRole(reason) {
  if (!reason) return 'Supporting Evidence';
  const colonIdx = reason.indexOf(':');
  if (colonIdx > 0 && colonIdx < 32) {
    return reason.slice(0, colonIdx).trim();
  }
  return 'Supporting Evidence';
}

/**
 * Step 5 & Step 6: Evidence drawer displaying raw events behind an activity
 * with rule, role, JSON highlighting, and "Export Forensic PDF" action.
 */
export function EvidenceDrawer({
  activity,
  loading,
  error,
  onClose,
  onExportPdf = downloadActivityReportPdf,
}) {
  const [exporting, setExporting] = useState(false);
  const [exportStatus, setExportStatus] = useState(null);

  useEffect(() => {
    setExportStatus(null);
    setExporting(false);
  }, [activity?.activity_id]);

  useEffect(() => {
    if (!activity && !loading && !error) return undefined;
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activity, loading, error, onClose]);

  if (!activity && !loading && !error) {
    return null;
  }

  const evidenceChain = activity?.evidence_chain || [];
  const mlScore =
    activity?.ml_anomaly_score !== null && activity?.ml_anomaly_score !== undefined
      ? Number(activity.ml_anomaly_score).toFixed(2)
      : 'Unavailable';

  const handleExportPdf = async () => {
    if (!activity?.activity_id) return;
    setExporting(true);
    setExportStatus(null);
    try {
      const result = await onExportPdf(activity.activity_id);
      console.info(
        `[dashboard.EvidenceDrawer] [RECEIVED] export activity=${activity.activity_id} -> [PRODUCED] Downloaded ${result?.filename || 'PDF'}`
      );
      setExportStatus({
        type: 'success',
        message: `Downloaded ${result?.filename || `ForensiTrace_Report_${activity.activity_id}.pdf`}`,
      });
    } catch (err) {
      console.error(
        `[dashboard.EvidenceDrawer] [RECEIVED] export activity=${activity.activity_id} -> [PRODUCED] Error: ${err.message}`
      );
      setExportStatus({
        type: 'error',
        message: `PDF export requires the live backend (/report/${activity.activity_id}): ${err.message}`,
      });
    } finally {
      setExporting(false);
    }
  };

  console.info(
    `[dashboard.EvidenceDrawer] [RECEIVED] activity=${activity?.activity_id || 'loading'} evidenceCount=${evidenceChain.length} -> [PRODUCED] Rendering explainability drawer`
  );

  return (
    <aside
      className="evidence-drawer-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label="Evidence Drawer"
      data-testid="evidence-drawer"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="evidence-drawer">
        <div className="drawer-header">
          <div>
            <span className="drawer-eyebrow">Explainability &amp; Raw Provenance</span>
            <h2 className="drawer-title">
              {activity ? `${activity.rule_id}: ${activity.rule_name}` : 'Loading Activity...'}
            </h2>
          </div>
          <div className="drawer-actions">
            {activity && (
              <button
                type="button"
                className="btn-export-pdf"
                onClick={handleExportPdf}
                disabled={exporting || loading}
                data-testid="export-pdf-btn"
              >
                {exporting ? 'Exporting PDF...' : 'Export Forensic PDF'}
              </button>
            )}
            <button
              type="button"
              className="btn-close-drawer"
              onClick={onClose}
              aria-label="Close evidence drawer"
              data-testid="close-evidence-drawer"
            >
              &times;
            </button>
          </div>
        </div>

        {exportStatus && (
          <div
            className={
              exportStatus.type === 'success'
                ? 'pdf-status-banner pdf-status-success'
                : 'pdf-status-banner pdf-status-error'
            }
            role="status"
            data-testid="pdf-export-status"
          >
            {exportStatus.message}
          </div>
        )}

        {loading && <div className="drawer-state">Loading supporting raw events...</div>}
        {error && <div className="drawer-error">{error}</div>}

        {!loading && !error && activity && (
          <div className="drawer-body">
            <div className="drawer-summary-grid">
              <div className="drawer-metric">
                <span>Rule Confidence</span>
                <strong>{Number(activity.confidence ?? 0).toFixed(2)}</strong>
              </div>
              <div className="drawer-metric">
                <span>ML Anomaly Score</span>
                <strong>{mlScore}</strong>
              </div>
              <div className="drawer-metric">
                <span>Threat Level</span>
                <strong>{activity.threat_level || 'MEDIUM'}</strong>
              </div>
            </div>

            {activity.narrative && (
              <p className="drawer-narrative">{activity.narrative}</p>
            )}

            <h3 className="drawer-section-heading">
              Raw Supporting Events ({evidenceChain.length})
            </h3>

            {evidenceChain.length === 0 ? (
              <div className="empty-state">
                No linked raw events returned for this activity.
              </div>
            ) : (
              <div className="evidence-events-list" data-testid="evidence-chain-list">
                {evidenceChain.map((ev, index) => {
                  const roleLabel = extractRole(ev.reason);
                  return (
                    <article
                      key={ev.event_id || index}
                      className="evidence-event-card"
                      data-testid={`evidence-event-${ev.event_id}`}
                    >
                      <div className="evidence-event-header">
                        <span className="rule-badge">
                          Rule: {ev.rule_id || activity.rule_id}
                        </span>
                        <span className="role-badge">Role: {roleLabel}</span>
                        <span className="source-pill">{ev.source}</span>
                        <span className="timeline-ts">{ev.ts_utc}</span>
                      </div>

                      <p className="evidence-reason">{ev.reason}</p>

                      <div className="evidence-meta-line">
                        <span>Action: <code>{ev.action}</code></span>
                        <span>Entity: <code>{ev.entity}</code></span>
                        <span>Host: <code>{ev.host}</code></span>
                        <span>User: <code>{ev.user || 'N/A'}</code></span>
                      </div>

                      <details open>
                        <summary className="json-summary">
                          Raw Telemetry JSON (<code>raw</code>)
                        </summary>
                        <JsonHighlight
                          data={ev.raw}
                          testId={`json-raw-${ev.event_id}`}
                        />
                      </details>

                      <details>
                        <summary className="json-summary">
                          Normalized Details JSON (<code>details</code>)
                        </summary>
                        <JsonHighlight
                          data={ev.details}
                          testId={`json-details-${ev.event_id}`}
                        />
                      </details>
                    </article>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

export default EvidenceDrawer;
