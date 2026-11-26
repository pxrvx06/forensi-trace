/**
 * ForensiTrace Dashboard API Client (Step 1).
 * Connects to Purva's FastAPI backend endpoints (backend/main.py & docs/ml.md).
 * Falls back cleanly to mock data when the API is unavailable or mock mode is selected.
 */

import {
  MOCK_ACTIVITIES,
  MOCK_EVENTS,
  MOCK_HEALTH,
  MOCK_TIMELINE,
} from './mockData';

const DEFAULT_API_BASE =
  (typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.VITE_API_BASE_URL) ||
  'http://127.0.0.1:8000';

function logApi(action, received, produced) {
  console.info(
    `[dashboard.api] [RECEIVED] ${action}: ${JSON.stringify(received)} -> [PRODUCED] ${JSON.stringify(produced)}`
  );
}

async function requestJson(path, baseUrl = DEFAULT_API_BASE) {
  const url = `${baseUrl}${path}`;
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from ${path}`);
  }
  return response.json();
}

export async function fetchHealth(baseUrl = DEFAULT_API_BASE) {
  logApi('GET /health', { baseUrl }, { status: 'requesting' });
  const data = await requestJson('/health', baseUrl);
  logApi('GET /health', { baseUrl }, { status: data.status });
  return data;
}

export async function fetchEvents(
  { source = '', action = '', host = '', limit = 100, offset = 0 } = {},
  baseUrl = DEFAULT_API_BASE
) {
  const params = new URLSearchParams();
  if (source) params.set('source', source);
  if (action) params.set('action', action);
  if (host) params.set('host', host);
  params.set('limit', String(limit));
  params.set('offset', String(offset));

  const query = params.toString();
  const data = await requestJson(`/events?${query}`, baseUrl);
  logApi('GET /events', { source, limit, offset }, { count: data.count });
  return data;
}

export async function fetchEventById(eventId, baseUrl = DEFAULT_API_BASE) {
  const data = await requestJson(`/events/${encodeURIComponent(eventId)}`, baseUrl);
  logApi('GET /events/{id}', { eventId }, { action: data.action });
  return data;
}

export async function fetchActivities(
  { limit = 100, offset = 0 } = {},
  baseUrl = DEFAULT_API_BASE
) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  const data = await requestJson(`/activities?${params.toString()}`, baseUrl);
  logApi('GET /activities', { limit, offset }, { count: data.count });
  return data;
}

export async function fetchActivityById(
  activityId,
  { useMock = false, baseUrl = DEFAULT_API_BASE } = {}
) {
  if (useMock) {
    const found = MOCK_ACTIVITIES.find((a) => a.activity_id === activityId) || null;
    logApi('MOCK GET /activities/{id}', { activityId }, { found: Boolean(found) });
    if (!found) {
      throw new Error(`Mock activity '${activityId}' not found`);
    }
    return found;
  }

  const data = await requestJson(
    `/activities/${encodeURIComponent(activityId)}`,
    baseUrl
  );
  logApi(
    'GET /activities/{id}',
    { activityId },
    { evidenceCount: Array.isArray(data.evidence_chain) ? data.evidence_chain.length : 0 }
  );
  return data;
}

export async function fetchTimeline(
  { limit = 200, offset = 0, source = '', order = 'asc' } = {},
  baseUrl = DEFAULT_API_BASE
) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    order,
  });
  if (source) params.set('source', source);

  const data = await requestJson(`/timeline?${params.toString()}`, baseUrl);
  logApi('GET /timeline', { source, order, limit }, { count: data.count });
  return data;
}

export function getReportPdfUrl(activityId, baseUrl = DEFAULT_API_BASE) {
  return `${baseUrl}/report/${encodeURIComponent(activityId)}`;
}

function parseDownloadFilename(contentDisposition, activityId) {
  if (contentDisposition) {
    const match = contentDisposition.match(/filename="?([^";]+)"?/i);
    if (match && match[1]) {
      return match[1];
    }
  }
  const safeId = String(activityId).replace(/[^a-zA-Z0-9_-]/g, '_');
  return `ForensiTrace_Report_${safeId}.pdf`;
}

export async function downloadActivityReportPdf(
  activityId,
  baseUrl = DEFAULT_API_BASE
) {
  const url = getReportPdfUrl(activityId, baseUrl);
  logApi('GET /report/{activity_id}', { activityId, url }, { status: 'requesting' });

  const response = await fetch(url, {
    headers: { Accept: 'application/pdf' },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from /report/${activityId}`);
  }

  const blob = await response.blob();
  const filename = parseDownloadFilename(
    response.headers.get('Content-Disposition'),
    activityId
  );

  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);

  logApi('GET /report/{activity_id}', { activityId }, { filename, bytes: blob.size });
  return { filename, bytes: blob.size };
}

export function getMockDashboardBundle(sourceFilter = '') {
  const events = sourceFilter
    ? MOCK_EVENTS.filter((ev) => ev.source === sourceFilter)
    : MOCK_EVENTS;
  const timeline = sourceFilter
    ? MOCK_TIMELINE.filter(
        (item) => item.type === 'event' && item.data.source === sourceFilter
      )
    : MOCK_TIMELINE;

  const bundle = {
    mode: 'mock',
    health: MOCK_HEALTH,
    events,
    activities: MOCK_ACTIVITIES,
    timeline,
  };
  logApi(
    'getMockDashboardBundle',
    { sourceFilter },
    {
      events: bundle.events.length,
      activities: bundle.activities.length,
      timeline: bundle.timeline.length,
    }
  );
  return bundle;
}

export async function loadDashboardBundle({
  preferMock = false,
  sourceFilter = '',
  baseUrl = DEFAULT_API_BASE,
} = {}) {
  if (preferMock) {
    return getMockDashboardBundle(sourceFilter);
  }

  try {
    const [health, eventsRes, activitiesRes, timelineRes] = await Promise.all([
      fetchHealth(baseUrl),
      fetchEvents({ limit: 500 }, baseUrl),
      fetchActivities({ limit: 100 }, baseUrl),
      fetchTimeline({ limit: 500, source: sourceFilter, order: 'asc' }, baseUrl),
    ]);

    const bundle = {
      mode: 'live',
      health,
      events: eventsRes.events || [],
      activities: activitiesRes.activities || [],
      timeline: timelineRes.timeline || [],
    };
    logApi(
      'loadDashboardBundle',
      { mode: 'live', sourceFilter },
      {
        events: bundle.events.length,
        activities: bundle.activities.length,
        timeline: bundle.timeline.length,
      }
    );
    return bundle;
  } catch (err) {
    console.warn(
      `[dashboard.api] [RECEIVED] Live API unreachable (${err.message}) -> [PRODUCED] Falling back to mock data`
    );
    return {
      ...getMockDashboardBundle(sourceFilter),
      fallbackReason: err.message,
    };
  }
}
