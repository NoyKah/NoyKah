// Demo data for IRHunter DFIR Tool

export const demoFiles = [
  {
    id: 'demo1',
    name: 'KAPE_Triage.zip',
    size: 2.5 * 1024 * 1024 * 1024, // 2.5GB
    type: 'application/zip',
    uploadedAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(), // 30 minutes ago
  },
  {
    id: 'demo2',
    name: 'EventLogs.7z',
    size: 890 * 1024 * 1024, // 890MB
    type: 'application/x-7z-compressed',
    uploadedAt: new Date(Date.now() - 25 * 60 * 1000).toISOString(), // 25 minutes ago
  },
  {
    id: 'demo3',
    name: 'Registry_Hives.tar',
    size: 156 * 1024 * 1024, // 156MB
    type: 'application/x-tar',
    uploadedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(), // 20 minutes ago
  }
];

export const demoCase = `What processes were executed between 14:00 and 15:00?
Find evidence of PowerShell execution with bypassed policies
Show me all registry modifications for persistence
What files were downloaded or created in Downloads folder?
Are there any suspicious network connections?
Find evidence of file deletion or anti-forensics techniques`;

export const demoReport = {
  caseId: 'CASE-DEMO-001',
  timestamp: new Date().toISOString(),
  confidence: 'Medium',
  summary: 'Analysis of 3 uploaded forensic files revealed evidence across 5 of 6 investigator questions. 3 high-confidence findings were identified through artifact correlation. The investigation focused on the specific questions provided and analyzed only the evidence present in the uploaded artifacts.',
  investigatorQuestions: [
    'What processes were executed between 14:00 and 15:00?',
    'Find evidence of PowerShell execution with bypassed policies',
    'Show me all registry modifications for persistence',
    'What files were downloaded or created in Downloads folder?',
    'Are there any suspicious network connections?',
    'Find evidence of file deletion or anti-forensics techniques'
  ],
  uploadedFiles: ['KAPE_Triage.zip', 'EventLogs.7z', 'Registry_Hives.tar'],
  artifactsAnalyzed: ['registry', 'eventLogs', 'prefetch', 'amcache', 'mft'],
  findings: [
    {
      category: 'Q1: What processes were executed between 14:00 and 15:00?',
      severity: 'High',
      description: 'Process execution detected within specified timeframe',
      evidence: 'Event ID 4688 process creation events, Prefetch file timestamps (Source: EventLogs.7z, KAPE_Triage.zip)',
      mitre: 'N/A',
      timestamp: '2024-01-15T14:23:15Z',
      details: 'PDFEditor.exe, powershell.exe executed between 14:00-15:00',
      confidence: 'High',
      artifactsSearched: 'Prefetch, Event Logs, Amcache'
    },
    {
      category: 'Q2: Find evidence of PowerShell execution with bypassed...',
      severity: 'High',
      description: 'PowerShell activity detected in uploaded artifacts',
      evidence: 'Prefetch analysis shows powershell.exe execution, Event logs contain PowerShell script block logging (Source: EventLogs.7z, KAPE_Triage.zip)',
      mitre: 'T1059.001',
      timestamp: '2024-01-15T14:24:30Z',
      details: 'PowerShell executed with -ExecutionPolicy Bypass parameters',
      confidence: 'High',
      artifactsSearched: 'Prefetch, Event Logs, Amcache'
    },
    {
      category: 'Q3: Show me all registry modifications for persistenc...',
      severity: 'High',
      description: 'Registry Run key modifications detected',
      evidence: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key analysis (Source: Registry_Hives.tar)',
      mitre: 'T1547.001',
      timestamp: '2024-01-15T14:25:00Z',
      details: 'UpdatePDFService value pointing to suspicious executable',
      confidence: 'High',
      artifactsSearched: 'Registry Hives'
    },
    {
      category: 'Q4: What files were downloaded or created in Downloads...',
      severity: 'High',
      description: 'Suspicious file downloads detected',
      evidence: 'Browser download history, MFT file creation records (Source: KAPE_Triage.zip)',
      mitre: 'N/A',
      timestamp: '2024-01-15T14:20:00Z',
      details: 'PDFEditor_Pro.zip downloaded from external source',
      confidence: 'High',
      artifactsSearched: 'MFT, Browser History'
    },
    {
      category: 'Q6: Find evidence of file deletion or anti-forensics...',
      severity: 'High',
      description: 'Evidence of file deletion detected',
      evidence: 'MFT analysis showing file deletion timestamps (Source: KAPE_Triage.zip)',
      mitre: 'T1070.004',
      timestamp: '2024-01-15T14:25:42Z',
      details: 'Original PDFEditor.exe deleted after execution',
      confidence: 'High',
      artifactsSearched: 'MFT, Browser History'
    }
  ],
  indicators: [
    'Registry modification detected in Registry_Hives.tar',
    'PowerShell execution with suspicious parameters',
    'File system activity: PDFEditor_Pro.zip downloaded from external source',
    'Activity timestamp: 2024-01-15T14:23:15Z',
    'Activity timestamp: 2024-01-15T14:24:30Z',
    'Activity timestamp: 2024-01-15T14:25:00Z',
    'Activity timestamp: 2024-01-15T14:20:00Z',
    'File system activity: Original PDFEditor.exe deleted after execution'
  ],
  recommendations: [
    'Investigate process execution timeline for additional malicious activity',
    'Check for process injection or hollow process techniques',
    'Monitor registry keys for additional persistence mechanisms',
    'Implement registry monitoring for similar modifications',
    'Perform file hash analysis against threat intelligence feeds',
    'Check for additional file modifications in system directories',
    'Continue monitoring the affected system for additional IOCs',
    'Review similar systems in the environment for compromise indicators'
  ],
  attackChain: [
    {
      stage: 'Initial Access + Execution',
      description: 'Social engineering via fake PDF editor leading to malware execution',
      timeframe: '2024-01-15T14:23:15Z to 2024-01-15T14:24:30Z',
      confidence: 'High',
      mitre: ['T1566.001', 'T1059.001']
    },
    {
      stage: 'Persistence + Defense Evasion',
      description: 'Registry modification for persistence followed by original file deletion',
      timeframe: '2024-01-15T14:25:00Z to 2024-01-15T14:25:42Z',
      confidence: 'High',
      mitre: ['T1547.001', 'T1070.004']
    },
    {
      stage: 'Discovery',
      description: 'System and network reconnaissance activities',
      timeframe: '2024-01-15T14:26:15Z onwards',
      confidence: 'Medium',
      mitre: ['T1016', 'T1033']
    }
  ]
};

export const demoArtifacts = {
  registry: { files: 5, entries: 1247 },
  eventLogs: { files: 12, events: 3421 },
  prefetch: { files: 127, executions: 198 },
  amcache: { entries: 456 },
  mft: { entries: 28934 },
  browserHistory: { entries: 234 },
  scheduledTasks: { tasks: 18 },
  services: { services: 67 }
};