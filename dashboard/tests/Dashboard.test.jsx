import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import DashboardPage from '../src/pages/DashboardPage';
import EvidenceDrawer from '../src/components/EvidenceDrawer';
import { MOCK_ACTIVITIES } from '../src/api/mockData';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ForensiTrace Dashboard (Steps 1-6)', () => {
  it('renders header health bar and 3 summary cards with mock data', async () => {
    render(<DashboardPage initialPreferMock />);

    expect(await screen.findByTestId('backend-status')).toHaveTextContent(
      'Mock Data Mode'
    );
    expect(screen.getByTestId('card-events-ingested')).toHaveTextContent('4');
    expect(screen.getByTestId('card-active-anomalies')).toHaveTextContent('2');
    expect(screen.getByTestId('card-correlated-activities')).toHaveTextContent('3');
  });

  it('displays rule confidence and ML score separately without percentage-of-risk wording', async () => {
    render(<DashboardPage initialPreferMock />);

    const r7Confidence = await screen.findByTestId('rule-confidence-act_r7_scenario_a01');
    const r7Ml = screen.getByTestId('ml-score-act_r7_scenario_a01');
    const r7Threat = screen.getByTestId('threat-level-act_r7_scenario_a01');

    expect(r7Confidence).toHaveTextContent('0.96');
    expect(r7Ml).toHaveTextContent('0.88');
    expect(r7Threat).toHaveTextContent('CRITICAL');

    // Graceful fallback when ML score is missing (null)
    const r1Ml = screen.getByTestId('ml-score-act_r1_usbfs01');
    expect(r1Ml).toHaveTextContent('Unavailable');

    // Must never describe ML score as percentage of risk
    expect(document.body.textContent).not.toMatch(/percentage of risk/i);
  });

  it('renders timeline with colour-coded source badges and filters by source', async () => {
    render(<DashboardPage initialPreferMock />);

    expect(await screen.findAllByTestId('source-badge-usb')).not.toHaveLength(0);
    expect(screen.getAllByTestId('source-badge-fs')).not.toHaveLength(0);
    expect(screen.getAllByTestId('source-badge-eventlog')).not.toHaveLength(0);

    fireEvent.click(screen.getByTestId('timeline-filter-usb'));
    expect(screen.getAllByTestId('source-badge-usb')).toHaveLength(1);
    expect(screen.queryByTestId('source-badge-fs')).toBeNull();
  });

  it('opens evidence drawer for rule-matched and ML-flagged activities with rule, role, and JSON highlighting', async () => {
    render(<DashboardPage initialPreferMock />);

    const inspectBtn = await screen.findByTestId('inspect-evidence-act_r7_scenario_a01');
    fireEvent.click(inspectBtn);

    const drawer = await screen.findByTestId('evidence-drawer');
    expect(drawer).toHaveTextContent('R7: Composite USB copy and execution chain');
    expect(drawer).toHaveTextContent('Role: Stage 1');
    expect(
      screen.getByTestId('json-raw-8fdfc64e74cc0d33ca188bff14a86a57ec8ac88f9569ea731ad171d9c67213e6')
    ).toHaveTextContent('DBT_DEVICEARRIVAL');

    fireEvent.click(screen.getByTestId('close-evidence-drawer'));
    await waitFor(() => {
      expect(screen.queryByTestId('evidence-drawer')).toBeNull();
    });
  });

  it('triggers PDF export and surfaces success or backend error cleanly', async () => {
    const mockExport = vi.fn().mockResolvedValue({
      filename: 'ForensiTrace_Report_act_r7_scenario_a01.pdf',
      bytes: 4096,
    });

    render(
      <EvidenceDrawer
        activity={MOCK_ACTIVITIES[0]}
        loading={false}
        error={null}
        onClose={vi.fn()}
        onExportPdf={mockExport}
      />
    );

    fireEvent.click(screen.getByTestId('export-pdf-btn'));

    await waitFor(() => {
      expect(mockExport).toHaveBeenCalledWith('act_r7_scenario_a01');
      expect(screen.getByTestId('pdf-export-status')).toHaveTextContent(
        'Downloaded ForensiTrace_Report_act_r7_scenario_a01.pdf'
      );
    });
  });
});
