import React from 'react';

const THREAT_CLASS = {
  CRITICAL: 'threat-critical',
  HIGH: 'threat-high',
  MEDIUM: 'threat-medium',
  LOW: 'threat-low',
};

function formatScore(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return null;
  }
  return Number(value).toFixed(2);
}

/**
 * Step 3: Activity feed showing:
 * - title (rule_name)
 * - matched rule (rule_id)
 * - rule confidence (separate field)
 * - ML anomaly badge (separate normalized reconstruction error 0.00-1.00)
 * - threat level (CRITICAL / HIGH / MEDIUM / LOW)
 * - narrative
 */
export function ActivityFeed({
  activities,
  selectedActivityId,
  onSelectActivity,
}) {
  console.info(
    `[dashboard.ActivityFeed] [RECEIVED] ${activities.length} activities -> [PRODUCED] Rendering activity cards`
  );

  return (
    <section className="panel activity-feed-panel" aria-label="Activity Feed">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Activity Feed</h2>
          <p className="panel-subtitle">
            Rule confidence and ML anomaly score shown side by side for each activity
          </p>
        </div>
        <span className="panel-count">{activities.length} total</span>
      </div>

      {activities.length === 0 ? (
        <div className="empty-state">No correlated activities found yet.</div>
      ) : (
        <div className="activity-list" data-testid="activity-feed-list">
          {activities.map((activity) => {
            const ruleConf = formatScore(activity.confidence);
            const mlScore = formatScore(activity.ml_anomaly_score);
            const threatLevel = (activity.threat_level || 'MEDIUM').toUpperCase();
            const isSelected = selectedActivityId === activity.activity_id;
            const isMlFlagged = mlScore !== null && Number(mlScore) >= 0.5;

            return (
              <article
                key={activity.activity_id}
                className={`activity-card ${isSelected ? 'activity-card-selected' : ''}`}
                data-testid={`activity-card-${activity.activity_id}`}
              >
                <div className="activity-card-top">
                  <div className="activity-badges-row">
                    <span className="rule-badge" title="Matched Correlation Rule">
                      {activity.rule_id}
                    </span>
                    <span
                      className={`threat-badge ${THREAT_CLASS[threatLevel] || 'threat-medium'}`}
                      data-testid={`threat-level-${activity.activity_id}`}
                    >
                      {threatLevel}
                    </span>
                    <span
                      className={`ml-badge ${
                        mlScore === null
                          ? 'ml-badge-unavailable'
                          : isMlFlagged
                          ? 'ml-badge-flagged'
                          : 'ml-badge-normal'
                      }`}
                      data-testid={`ml-badge-${activity.activity_id}`}
                      title="Normalized autoencoder reconstruction error (0.00 to 1.00)"
                    >
                      {mlScore !== null
                        ? `ML Anomaly: ${mlScore}`
                        : 'ML Anomaly: Unavailable'}
                    </span>
                  </div>
                  <span className="activity-time">
                    {activity.ts_start_utc} &rarr; {activity.ts_end_utc}
                  </span>
                </div>

                <h3 className="activity-title">{activity.rule_name}</h3>

                <div className="scores-row">
                  <div className="score-box" data-testid={`rule-confidence-${activity.activity_id}`}>
                    <span className="score-label">Rule Confidence</span>
                    <span className="score-value">{ruleConf ?? 'N/A'}</span>
                  </div>
                  <div className="score-box" data-testid={`ml-score-${activity.activity_id}`}>
                    <span className="score-label">ML Score (Norm. Error)</span>
                    <span className="score-value">{mlScore ?? 'Unavailable'}</span>
                  </div>
                </div>

                <p className="activity-narrative">
                  {activity.narrative || 'No narrative generated for this activity.'}
                </p>

                <div className="activity-card-footer">
                  <code className="activity-id-code">{activity.activity_id}</code>
                  <button
                    type="button"
                    className="btn-inspect"
                    onClick={() => onSelectActivity(activity.activity_id)}
                    data-testid={`inspect-evidence-${activity.activity_id}`}
                  >
                    Inspect Evidence
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default ActivityFeed;
