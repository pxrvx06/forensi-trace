import React from 'react';

/**
 * Step 2: Header and health bar with backend status and summary cards:
 * - Events Ingested
 * - Active Anomalies
 * - Correlated Activities
 */
export function HeaderHealthBar({
  mode,
  health,
  fallbackReason,
  eventsCount,
  activeAnomaliesCount,
  activitiesCount,
  preferMock,
  onToggleMock,
  onRefresh,
  loading,
}) {
  const isLive = mode === 'live' && health?.status === 'ok';

  console.info(
    `[dashboard.HeaderHealthBar] [RECEIVED] mode=${mode} events=${eventsCount} anomalies=${activeAnomaliesCount} activities=${activitiesCount} -> [PRODUCED] Rendered header and 3 summary cards`
  );

  return (
    <header className="dashboard-header" data-testid="header-health-bar">
      <div className="header-top-row">
        <div className="brand-block">
          <div className="brand-title-row">
            <span className="brand-mark" aria-hidden="true">
              FT
            </span>
            <div>
              <h1 className="brand-title">ForensiTrace</h1>
              <p className="brand-subtitle">
                Hybrid Rule Correlation &amp; Sequence Anomaly Investigation Console
              </p>
            </div>
          </div>
        </div>

        <div className="health-controls">
          <div
            className={`health-pill ${isLive ? 'health-online' : 'health-mock'}`}
            data-testid="backend-status"
          >
            <span className="health-dot" aria-hidden="true" />
            <span>
              {isLive
                ? 'Backend Online (Live API)'
                : preferMock
                ? 'Mock Data Mode'
                : 'Backend Offline (Mock Fallback)'}
            </span>
          </div>

          {health?.timestamp_utc && (
            <span className="health-timestamp" title="Backend health timestamp">
              UTC: {health.timestamp_utc}
            </span>
          )}

          <button
            type="button"
            className="btn-control"
            onClick={onToggleMock}
            data-testid="toggle-mode-btn"
          >
            {preferMock ? 'Try Live API' : 'Use Mock Data'}
          </button>

          <button
            type="button"
            className="btn-control btn-primary"
            onClick={onRefresh}
            disabled={loading}
            data-testid="refresh-btn"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {fallbackReason && !preferMock && (
        <div className="fallback-banner" role="status">
          Live API unreachable ({fallbackReason}). Rendering validated mock telemetry.
        </div>
      )}

      <div className="summary-cards-grid">
        <article className="summary-card" data-testid="card-events-ingested">
          <span className="summary-label">Events Ingested</span>
          <strong className="summary-value">{eventsCount}</strong>
          <span className="summary-hint">Normalized USB, FS &amp; Event Log records</span>
        </article>

        <article className="summary-card summary-card-anomaly" data-testid="card-active-anomalies">
          <span className="summary-label">Active Anomalies</span>
          <strong className="summary-value">{activeAnomaliesCount}</strong>
          <span className="summary-hint">Activities with ML anomaly score &ge; 0.50</span>
        </article>

        <article className="summary-card" data-testid="card-correlated-activities">
          <span className="summary-label">Correlated Activities</span>
          <strong className="summary-value">{activitiesCount}</strong>
          <span className="summary-hint">Rule-reconstructed activity chains (R1&ndash;R7)</span>
        </article>
      </div>
    </header>
  );
}

export default HeaderHealthBar;
