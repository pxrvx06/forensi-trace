/**
 * Mock data for ForensiTrace React Dashboard (Step 1).
 * Mirrors backend/main.py response formats and Scenario A / C structures
 * from scenarios/ground_truth/ and docs/ml.md.
 */

export const MOCK_HEALTH = {
  status: 'ok',
  service: 'ForensiTrace Ingestion & Forensics API (Mock)',
  timestamp_utc: '2026-10-23T10:03:00.000Z',
};

export const MOCK_EVENTS = [
  {
    event_id: '8fdfc64e74cc0d33ca188bff14a86a57ec8ac88f9569ea731ad171d9c67213e6',
    source: 'usb',
    ts_utc: '2026-10-23T10:00:00.120Z',
    host: 'WIN-FORENSIC-01',
    user: 'SYSTEM',
    action: 'DEVICE_ARRIVED',
    entity_type: 'device',
    entity: 'E: (SanDisk Ultra 4C53000123456789)',
    details: {
      drive_letter: 'E:',
      device_name: 'SanDisk Ultra',
      serial_number: '4C53000123456789',
      vendor_id: '0781',
      product_id: '5581',
      raw_record_id: 'USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C53000123456789',
      scenario_id: 'scenario_a',
    },
    raw: {
      DeviceInstanceId: 'USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C53000123456789&0',
      Class: 'DiskDrive',
      FriendlyName: 'SanDisk Ultra USB Device',
      DriveLetter: 'E:',
      EventType: 'DBT_DEVICEARRIVAL',
    },
  },
  {
    event_id: '8376a88fcb952b02739e8f45c59bfba2c381de2b6140e44551b03832d5d149a7',
    source: 'fs',
    ts_utc: '2026-10-23T10:01:15.450Z',
    host: 'WIN-FORENSIC-01',
    user: null,
    action: 'FILE_CREATED',
    entity_type: 'file',
    entity: 'E:\\reports\\payload.exe',
    details: {
      drive_letter: 'E:',
      file_path: 'E:\\reports\\payload.exe',
      file_name: 'payload.exe',
      extension: '.exe',
      file_size_bytes: 1048576,
      is_directory: false,
      raw_record_id: 'FILE_CREATED|E:\\reports\\payload.exe',
      scenario_id: 'scenario_a',
    },
    raw: {
      event_type: 'created',
      src_path: 'E:\\reports\\payload.exe',
      is_directory: false,
    },
  },
  {
    event_id: '4c395da15ffecd0dde5685f9e03bd59a43b26d38235fcf72bb695711dfc7d2e3',
    source: 'eventlog',
    ts_utc: '2026-10-23T10:02:30.800Z',
    host: 'WIN-FORENSIC-01',
    user: 'CONTOSO\\analyst',
    action: 'PROCESS_STARTED',
    entity_type: 'process',
    entity: 'E:\\reports\\payload.exe',
    details: {
      drive_letter: 'E:',
      event_record_id: 9481942,
      channel: 'Security',
      event_code: 4688,
      process_id: '0x1a2c',
      process_name: 'E:\\reports\\payload.exe',
      parent_process_id: '0x0e20',
      parent_process_name: 'C:\\Windows\\explorer.exe',
      command_line: '"E:\\reports\\payload.exe"',
      raw_record_id: 'Security:9481942',
      scenario_id: 'scenario_a',
    },
    raw: {
      Event: {
        System: {
          Provider: { Name: 'Microsoft-Windows-Security-Auditing' },
          EventID: 4688,
          EventRecordID: 9481942,
          Channel: 'Security',
          Computer: 'WIN-FORENSIC-01',
          TimeCreated: { SystemTime: '2026-10-23T10:02:30.800Z' },
        },
        EventData: {
          NewProcessName: 'E:\\reports\\payload.exe',
          ProcessId: '0x1a2c',
          CommandLine: '"E:\\reports\\payload.exe"',
          ParentProcessName: 'C:\\Windows\\explorer.exe',
          SubjectUserName: 'analyst',
          SubjectDomainName: 'CONTOSO',
        },
      },
    },
  },
  {
    event_id: 'd2f7a441b9e8c31a60f8e12b74a9c0031982e3b4a5d6c7e8f9a0b1c2d3e4f501',
    source: 'eventlog',
    ts_utc: '2026-10-23T10:04:10.000Z',
    host: 'WIN-FORENSIC-01',
    user: 'CONTOSO\\analyst',
    action: 'LOG_CLEARED',
    entity_type: 'process',
    entity: 'Security',
    details: {
      event_record_id: 9482011,
      channel: 'Security',
      event_code: 1102,
      raw_record_id: 'Security:9482011',
      scenario_id: 'scenario_c',
    },
    raw: {
      Event: {
        System: {
          Provider: { Name: 'Microsoft-Windows-Eventlog' },
          EventID: 1102,
          EventRecordID: 9482011,
          Channel: 'Security',
          Computer: 'WIN-FORENSIC-01',
          TimeCreated: { SystemTime: '2026-10-23T10:04:10.000Z' },
        },
      },
    },
  },
];

export const MOCK_ACTIVITIES = [
  {
    activity_id: 'act_r7_scenario_a01',
    rule_id: 'R7',
    rule_name: 'Composite USB copy and execution chain',
    ts_start_utc: '2026-10-23T10:00:00.120Z',
    ts_end_utc: '2026-10-23T10:02:30.800Z',
    confidence: 0.96,
    ml_anomaly_score: 0.88,
    threat_level: 'CRITICAL',
    narrative:
      "Removable storage device 'SanDisk Ultra' mounted on volume E: at 2026-10-23T10:00:00.120Z [event:8fdfc64e], followed by file created for 'E:\\reports\\payload.exe' at 2026-10-23T10:01:15.450Z [event:8376a88f], and process execution under user 'CONTOSO\\analyst' at 2026-10-23T10:02:30.800Z [event:4c395da1]. [ML Analysis: Sequence anomaly score=0.88, combined risk index: 0.92, threat level: CRITICAL. Unusual executable staging sequence from removable media. Note: Anomaly score reflects statistical deviation from baseline activity, not proof of malicious intent.]",
    created_at_utc: '2026-10-23T10:02:31.000Z',
    evidence_chain: [
      {
        ...MOCK_EVENTS[0],
        rule_id: 'R7',
        reason: 'Stage 1: Removable USB storage arrival mounted on E:',
      },
      {
        ...MOCK_EVENTS[1],
        rule_id: 'R7',
        reason: 'Stage 2: Executable payload written to removable volume (FILE_CREATED)',
      },
      {
        ...MOCK_EVENTS[2],
        rule_id: 'R7',
        reason: 'Stage 3: Process executed from payload path within 900s chain window',
      },
    ],
  },
  {
    activity_id: 'act_r5_logclear01',
    rule_id: 'R5',
    rule_name: 'Log clearing near other activity',
    ts_start_utc: '2026-10-23T10:02:30.800Z',
    ts_end_utc: '2026-10-23T10:04:10.000Z',
    confidence: 0.91,
    ml_anomaly_score: 0.79,
    threat_level: 'HIGH',
    narrative:
      "Security event log was cleared at 2026-10-23T10:04:10.000Z [event:d2f7a441] within 99s of process execution 'E:\\reports\\payload.exe' [event:4c395da1]. [ML Analysis: Sequence anomaly score=0.79, combined risk index: 0.85, threat level: HIGH. Rare log-clearing sequence near process start. Note: Anomaly score reflects statistical deviation from baseline activity, not proof of malicious intent.]",
    created_at_utc: '2026-10-23T10:04:11.000Z',
    evidence_chain: [
      {
        ...MOCK_EVENTS[2],
        rule_id: 'R5',
        reason: 'Correlated Context: Process started 99s before Security log clearance',
      },
      {
        ...MOCK_EVENTS[3],
        rule_id: 'R5',
        reason: 'Trigger: Security log cleared (Event ID 1102)',
      },
    ],
  },
  {
    activity_id: 'act_r1_usbfs01',
    rule_id: 'R1',
    rule_name: 'Device arrival followed by file activity',
    ts_start_utc: '2026-10-23T10:00:00.120Z',
    ts_end_utc: '2026-10-23T10:01:15.450Z',
    confidence: 0.84,
    ml_anomaly_score: null,
    threat_level: 'HIGH',
    narrative:
      "Removable storage device 'SanDisk Ultra' mounted on volume E: at 2026-10-23T10:00:00.120Z [event:8fdfc64e], followed by file created for 'E:\\reports\\payload.exe' at 2026-10-23T10:01:15.450Z [event:8376a88f] after 75s (within 300s threshold). [ML Analysis: Tier 1 anomaly evaluation unavailable.]",
    created_at_utc: '2026-10-23T10:01:16.000Z',
    evidence_chain: [
      {
        ...MOCK_EVENTS[0],
        rule_id: 'R1',
        reason: 'Trigger: Removable USB storage arrival on E:',
      },
      {
        ...MOCK_EVENTS[1],
        rule_id: 'R1',
        reason: 'Target: File created on matching removable volume E:',
      },
    ],
  },
];

export const MOCK_TIMELINE = [
  {
    type: 'event',
    ts_utc: MOCK_EVENTS[0].ts_utc,
    data: MOCK_EVENTS[0],
  },
  {
    type: 'activity',
    ts_utc: MOCK_ACTIVITIES[0].ts_start_utc,
    data: MOCK_ACTIVITIES[0],
  },
  {
    type: 'activity',
    ts_utc: MOCK_ACTIVITIES[2].ts_start_utc,
    data: MOCK_ACTIVITIES[2],
  },
  {
    type: 'event',
    ts_utc: MOCK_EVENTS[1].ts_utc,
    data: MOCK_EVENTS[1],
  },
  {
    type: 'event',
    ts_utc: MOCK_EVENTS[2].ts_utc,
    data: MOCK_EVENTS[2],
  },
  {
    type: 'activity',
    ts_utc: MOCK_ACTIVITIES[1].ts_start_utc,
    data: MOCK_ACTIVITIES[1],
  },
  {
    type: 'event',
    ts_utc: MOCK_EVENTS[3].ts_utc,
    data: MOCK_EVENTS[3],
  },
];
