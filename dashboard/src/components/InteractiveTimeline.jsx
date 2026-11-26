import React, { useMemo, useState } from 'react';

const SOURCE_META = {
  usb: { label: 'USB', badgeClass: 'source-badge-usb' },
  fs: { label: 'File System', badgeClass: 'source-badge-fs' },
  eventlog: { label: 'Event Log', badgeClass: 'source-badge-eventlog' },
};

function formatShortTime(tsUtc) {
  if (!tsUtc) return 'N/A';
  const tIndex = tsUtc.indexOf('T');
  if (tIndex === -1) return tsUtc;
  return tsUtc.slice(tIndex + 1).replace('Z', ' UTC');
}

/**
 * Step 4: Interactive timeline with colour-coded source badges (USB, File System, Event Log)
 * Consumes GET /timeline items ({ type: "event" | "activity", ts_utc, data }).
 */
export function InteractiveTimeline({
  timeline,
  selectedActivityId,
  onSelectActivity,
}) {
  const [filterType, setFilterType] = useState('all');
  const [selectedEventId, setSelectedEventId] = useState(null);

  const filteredItems = useMemo(() => {
    const items = timeline.filter((item) => {
      if (filterType === 'all') return true;
      if (filterType === 'activity') return item.type === 'activity';
      return item.type === 'event' && item.data?.source === filterType;
    });
    return items;
  }, [timeline, filterType]);

  console.info(
    `[dashboard.InteractiveTimeline] [RECEIVED] total=${timeline.length} filter=${filterType} -> [PRODUCED] Showing ${filteredItems.length} timeline nodes`
  );

  return (
    <section className="panel timeline-panel" aria-label="Interactive Timeline">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Interactive Timeline</h2>
          <p className="panel-subtitle">
            Chronological chain of USB, File System, Event Log, and correlated activities
          </p>
        </div>

        <div className="timeline-filters" role="group" aria-label="Filter timeline by source">
          {[
            { id: 'all', label: 'All' },
            { id: 'usb', label: 'USB' },
            { id: 'fs', label: 'File System' },
            { id: 'eventlog', label: 'Event Log' },
            { id: 'activity', label: 'Activities' },
          ].map((btn) => (
            <button
              key={btn.id}
              type="button"
              className={`filter-pill ${filterType === btn.id ? 'filter-pill-active' : ''}`}
              onClick={() => setFilterType(btn.id)}
              data-testid={`timeline-filter-${btn.id}`}
            >
              {btn.label}
            </button>
          ))}
        </div>
      </div>

      {filteredItems.length === 0 ? (
        <div className="empty-state">No timeline entries match the current filter.</div>
      ) : (
        <ol className="timeline-axis" data-testid="timeline-list">
          {filteredItems.map((item, idx) => {
            if (item.type === 'activity') {
              const act = item.data || {};
              const isSelected = selectedActivityId === act.activity_id;
              return (
                <li
                  key={`act-${act.activity_id}-${idx}`}
                  className={`timeline-node timeline-node-activity ${
                    isSelected ? 'timeline-node-selected' : ''
                  }`}
                >
                  <div className="timeline-marker timeline-marker-activity" aria-hidden="true" />
                  <div className="timeline-content">
                    <div className="timeline-meta-row">
                      <span className="source-badge source-badge-activity">
                        Activity ({act.rule_id})
                      </span>
                      <span className="timeline-ts">{formatShortTime(item.ts_utc)}</span>
                      {act.threat_level && (
                        <span className="timeline-threat-tag">{act.threat_level}</span>
                      )}
                    </div>
                    <div className="timeline-entity-row">
                      <strong>{act.rule_name}</strong>
                      <button
                        type="button"
                        className="btn-link-inline"
                        onClick={() => onSelectActivity(act.activity_id)}
                        data-testid={`timeline-open-activity-${act.activity_id}`}
                      >
                        Open Evidence Drawer &rarr;
                      </button>
                    </div>
                  </div>
                </li>
              );
            }

            const ev = item.data || {};
            const meta = SOURCE_META[ev.source] || {
              label: ev.source || 'Unknown',
              badgeClass: 'source-badge-default',
            };
            const isExpanded = selectedEventId === ev.event_id;

            return (
              <li
                key={`ev-${ev.event_id || idx}`}
                className={`timeline-node ${isExpanded ? 'timeline-node-expanded' : ''}`}
              >
                <div className={`timeline-marker timeline-marker-${ev.source || 'default'}`} aria-hidden="true" />
                <div className="timeline-content">
                  <div className="timeline-meta-row">
                    <span
                      className={`source-badge ${meta.badgeClass}`}
                      data-testid={`source-badge-${ev.source}`}
                    >
                      {meta.label}
                    </span>
                    <span className="timeline-action">{ev.action}</span>
                    <span className="timeline-ts">{formatShortTime(item.ts_utc)}</span>
                  </div>

                  <div className="timeline-entity-row">
                    <code className="timeline-entity">{ev.entity}</code>
                    <button
                      type="button"
                      className="btn-link-inline"
                      onClick={() =>
                        setSelectedEventId(isExpanded ? null : ev.event_id)
                      }
                      data-testid={`timeline-toggle-event-${ev.event_id}`}
                    >
                      {isExpanded ? 'Hide Details' : 'Inspect Event'}
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="timeline-event-detail" data-testid={`timeline-event-detail-${ev.event_id}`}>
                      <div>
                        <span>Host:</span> <code>{ev.host}</code>
                      </div>
                      <div>
                        <span>User:</span> <code>{ev.user || 'N/A'}</code>
                      </div>
                      <div>
                        <span>Event ID:</span> <code>{ev.event_id}</code>
                      </div>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

export default InteractiveTimeline;
