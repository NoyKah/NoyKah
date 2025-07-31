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

export const demoCase = `Employee downloaded suspicious PDF editor from unknown site; malware self-deleted after execution.

Initial Analysis:
- User reported downloading "PDFEditor_Pro.zip" from external website
- EDR alert triggered by PDFEditor.exe execution at 14:23:15
- Subsequent PowerShell activity detected with bypassed execution policy
- Original executable disappeared after execution
- User mentioned system became "sluggish" after installation

Suspected Activities:
- Initial access via social engineering
- Potential persistence mechanisms
- Defense evasion techniques
- Possible data exfiltration`;

export const demoReport = {
  caseId: 'CASE-DEMO-001',
  timestamp: new Date().toISOString(),
  confidence: 'High',
  summary: 'Comprehensive analysis revealed a sophisticated malware infection with multiple stages. The attack began with a social engineering vector (fake PDF editor), progressed through initial execution, established persistence via registry modifications, and employed defense evasion techniques including self-deletion of the original payload.',
  findings: [
    {
      category: 'Initial Access',
      severity: 'High',
      description: 'Suspicious PDF editor application (PDFEditor.exe) was downloaded and executed from user Downloads folder. This represents a social engineering attack vector targeting the user with seemingly legitimate software.',
      evidence: 'Prefetch analysis shows first execution at 2024-01-15T14:23:15Z, Browser download history, File creation timestamp analysis',
      mitre: 'T1566.001',
      timestamp: '2024-01-15T14:23:15Z'
    },
    {
      category: 'Execution',
      severity: 'Critical',
      description: 'PowerShell was executed with bypassed execution policy approximately 75 seconds after initial infection. Command line analysis reveals script execution from temporary directory with suspicious parameters.',
      evidence: 'Security Event Log 4688, Process execution timeline, Command line: "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\temp\\update.ps1"',
      mitre: 'T1059.001',
      timestamp: '2024-01-15T14:24:30Z'
    },
    {
      category: 'Persistence',
      severity: 'High',
      description: 'Registry Run key was modified to establish automatic startup persistence. A suspicious executable was placed in the user AppData directory and configured to run at system startup.',
      evidence: 'Registry analysis: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdatePDFService = "C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe"',
      mitre: 'T1547.001',
      timestamp: '2024-01-15T14:25:00Z'
    },
    {
      category: 'Defense Evasion',
      severity: 'High',
      description: 'Original malware executable performed self-deletion after successfully establishing persistence. This technique is used to avoid detection and complicate forensic analysis.',
      evidence: 'MFT analysis showing file deletion timestamp, Absence of original PDFEditor.exe in Downloads folder, File system timeline correlation',
      mitre: 'T1070.004',
      timestamp: '2024-01-15T14:25:42Z'
    },
    {
      category: 'Discovery',
      severity: 'Medium',
      description: 'Evidence of system reconnaissance activities including network adapter enumeration and user account discovery. These activities suggest preparation for potential lateral movement.',
      evidence: 'PowerShell history showing Get-NetAdapter and Get-LocalUser cmdlets, Event ID 4104 (PowerShell Script Block Logging)',
      mitre: 'T1016',
      timestamp: '2024-01-15T14:26:15Z'
    }
  ],
  indicators: [
    'PDFEditor.exe (SHA256: a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890)',
    'C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe (Malicious persistence executable)',
    'Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdatePDFService',
    'PowerShell script: C:\\temp\\update.ps1',
    'Network connection to 192.168.1.100:4444 (Suspicious external IP)',
    'File hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    'User-Agent: "PDFEditor/1.0 (Windows NT 10.0; Win64; x64)"',
    'DNS query: malicious-update-server.com'
  ],
  recommendations: [
    'Immediately isolate the affected system from the network to prevent potential lateral movement and data exfiltration',
    'Search for additional instances of "UpdatePDFService" registry keys and "svchost.exe" in AppData directories across the environment',
    'Analyze C:\\temp\\update.ps1 script contents if still present, or check PowerShell history and script block logs for command details',
    'Review email logs and web proxy logs to identify the initial download source and potential other victims',
    'Update EDR rules to detect PowerShell execution with "-ExecutionPolicy Bypass" parameters and similar suspicious command line patterns',
    'Implement application whitelisting policies to prevent execution of unsigned or untrusted executables from user directories',
    'Conduct memory analysis of the affected system if still running to identify additional in-memory artifacts and network connections',
    'Check for signs of data exfiltration by analyzing network logs for unusual outbound traffic patterns',
    'Review Windows Defender or antivirus logs to determine if the malware was detected but allowed to execute',
    'Implement enhanced monitoring for registry modifications in Run keys and other common persistence locations'
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