import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  downloadActivityReportPdf,
  fetchActivityById,
  loadDashboardBundle,
} from '../api/client';
import HeaderHealthBar from '../components/HeaderHealthBar';
import ActivityFeed from '../components/ActivityFeed';
import InteractiveTimeline from '../components/InteractiveTimeline';
import EvidenceDrawer from '../components/EvidenceDrawer';

export function DashboardPage({ initialPreferMock = false }) {
  const [preferMock, setPreferMock] = useState(initialPreferMock);
  const [bundle, setBundle] = useState({
    mode: initialPreferMock ? 'mock' : 'loading',
    health: null,
    events: [],
    activities: [],
    timeline: [],
    fallbackReason: null,
  });
  const [loading, setLoading] = useState(true);

  const [selectedActivityId, setSelectedActivityId] = useState(null);
  const [drawerActivity, setDrawerActivity] = useState(null);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState(null);

  const loadData = useCallback(async (mockPreference) => {
    setLoading(true);
    const result = await loadDashboardBundle({ preferMock: mockPreference });
    console.info(
      `[dashboard.DashboardPage] [RECEIVED] preferMock=${mockPreference} -> [PRODUCED] Loaded mode=${result.mode}, events=${result.events.length}, activities=${result.activities.length}`
    );
    setBundle(result);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadData(preferMock);
  }, [preferMock, loadData]);

  const activeAnomaliesCount = useMemo(
    () =>
      bundle.activities.filter(
        (act) =>
          act.ml_anomaly_score !== null &&
          act.ml_anomaly_score !== undefined &&
          Number(act.ml_anomaly_score) >= 0.5
      ).length,
    [bundle.activities]
  );

  const handleSelectActivity = useCallback(
    async (activityId) => {
      setSelectedActivityId(activityId);
      setDrawerLoading(true);
      setDrawerError(null);

      try {
        const useMock = bundle.mode !== 'live';
        const fullActivity = await fetchActivityById(activityId, { useMock });
        console.info(
          `[dashboard.DashboardPage] [RECEIVED] activityId=${activityId} -> [PRODUCED] Opened evidence drawer with ${fullActivity.evidence_chain?.length ?? 0} event(s)`
        );
        setDrawerActivity(fullActivity);
      } catch (err) {
        console.error(
          `[dashboard.DashboardPage] [RECEIVED] activityId=${activityId} -> [PRODUCED] Error: ${err.message}`
        );
        setDrawerError(`Unable to load evidence chain: ${err.message}`);
      } finally {
        setDrawerLoading(false);
      }
    },
    [bundle.mode]
  );

  const handleCloseDrawer = useCallback(() => {
    setSelectedActivityId(null);
    setDrawerActivity(null);
    setDrawerError(null);
  }, []);

  return (
    <div className="dashboard-shell">
      <HeaderHealthBar
        mode={bundle.mode}
        health={bundle.health}
        fallbackReason={bundle.fallbackReason}
        eventsCount={bundle.events.length}
        activeAnomaliesCount={activeAnomaliesCount}
        activitiesCount={bundle.activities.length}
        preferMock={preferMock}
        onToggleMock={() => setPreferMock((prev) => !prev)}
        onRefresh={() => loadData(preferMock)}
        loading={loading}
      />

      <main className="dashboard-main-grid">
        <ActivityFeed
          activities={bundle.activities}
          selectedActivityId={selectedActivityId}
          onSelectActivity={handleSelectActivity}
        />

        <InteractiveTimeline
          timeline={bundle.timeline}
          selectedActivityId={selectedActivityId}
          onSelectActivity={handleSelectActivity}
        />
      </main>

      {(selectedActivityId || drawerLoading || drawerError) && (
        <EvidenceDrawer
          activity={drawerActivity}
          loading={drawerLoading}
          error={drawerError}
          onClose={handleCloseDrawer}
          onExportPdf={(actId) => downloadActivityReportPdf(actId)}
        />
      )}
    </div>
  );
}

export default DashboardPage;
