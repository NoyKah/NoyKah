// Mock AI service for demonstration
class MockAIService {
  async generate({ prompt, temperature, maxTokens }) {
    // Simulate AI processing delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Return mock analysis based on prompt content
    return `Based on the forensic evidence provided, I've identified several concerning indicators:

1. INITIAL ACCESS: Suspicious PDF editor download and execution
2. EXECUTION: PowerShell invocation with bypassed execution policy
3. PERSISTENCE: Registry Run key modification for automatic startup
4. DEFENSE EVASION: Self-deletion of original malware executable

The attack pattern suggests a sophisticated threat actor using social engineering to deliver malware, followed by establishing persistence and covering tracks. Immediate containment and investigation of related systems is recommended.`;
  }
}

// DFIR Investigation API
class InvestigationAPI {
  constructor() {
    this.aiModel = new MockAIService();
  }

  /**
   * Analyze uploaded forensic evidence files
   */
  async analyzeEvidence(files, caseDescription, progressCallback) {
    try {
      // Step 1: Extract and parse artifacts (20% progress)
      progressCallback(10);
      const extractedArtifacts = await this.extractArtifacts(files);
      progressCallback(20);

      // Step 2: Parse individual artifact types (40% progress)
      const parsedArtifacts = await this.parseArtifacts(extractedArtifacts);
      progressCallback(40);

      // Step 3: Correlate evidence across artifacts (60% progress)
      const correlatedEvidence = await this.correlateEvidence(parsedArtifacts);
      progressCallback(60);

      // Step 4: Generate AI investigation report (100% progress)
      const report = await this.generateReport(correlatedEvidence, caseDescription);
      progressCallback(100);

      return {
        report,
        artifacts: extractedArtifacts,
        correlations: correlatedEvidence
      };

    } catch (error) {
      console.error('Investigation analysis failed:', error);
      throw new Error(`Investigation failed: ${error.message}`);
    }
  }

  /**
   * Extract artifacts from uploaded files
   */
  async extractArtifacts(files) {
    const artifacts = {
      registry: { files: [], entries: 0 },
      eventLogs: { files: [], events: 0 },
      prefetch: { files: [], executions: 0 },
      amcache: { entries: 0, applications: [] },
      mft: { entries: 0, timeline: [] },
      browserHistory: { entries: 0, downloads: [] },
      scheduledTasks: { tasks: [] },
      services: { services: [] },
      networkConnections: { connections: [] }
    };

    for (const file of files) {
      // Simulate artifact extraction based on file names and content
      if (file.name.toLowerCase().includes('registry') || file.name.includes('.hiv')) {
        artifacts.registry.files.push(file.name);
        artifacts.registry.entries += Math.floor(Math.random() * 2000) + 500;
      }
      
      if (file.name.toLowerCase().includes('event') || file.name.includes('.evtx')) {
        artifacts.eventLogs.files.push(file.name);
        artifacts.eventLogs.events += Math.floor(Math.random() * 5000) + 1000;
      }
      
      if (file.name.toLowerCase().includes('prefetch') || file.name.includes('.pf')) {
        artifacts.prefetch.files.push(file.name);
        artifacts.prefetch.executions += Math.floor(Math.random() * 200) + 50;
      }
      
      if (file.name.toLowerCase().includes('amcache')) {
        artifacts.amcache.entries += Math.floor(Math.random() * 500) + 100;
      }
      
      if (file.name.toLowerCase().includes('mft') || file.name.includes('$MFT')) {
        artifacts.mft.entries += Math.floor(Math.random() * 50000) + 10000;
      }
    }

    return artifacts;
  }

  /**
   * Parse extracted artifacts into structured data
   */
  async parseArtifacts(artifacts) {
    const parsedData = {
      timeline: [],
      executedProcesses: [],
      networkActivity: [],
      fileSystemChanges: [],
      registryModifications: [],
      persistenceMechanisms: []
    };

    // Simulate parsing Windows artifacts
    if (artifacts.prefetch.executions > 0) {
      parsedData.executedProcesses = [
        {
          name: 'PDFEditor.exe',
          path: 'C:\\Users\\User\\Downloads\\PDFEditor.exe',
          firstRun: '2024-01-15T14:23:15Z',
          lastRun: '2024-01-15T14:25:42Z',
          runCount: 2,
          hash: 'SHA256:a1b2c3d4e5f6789...'
        },
        {
          name: 'powershell.exe',
          path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          firstRun: '2024-01-15T14:24:30Z',
          lastRun: '2024-01-15T14:24:45Z',
          runCount: 1,
          commandLine: '-ExecutionPolicy Bypass -File C:\\temp\\update.ps1'
        }
      ];
    }

    if (artifacts.registry.entries > 0) {
      parsedData.persistenceMechanisms = [
        {
          type: 'Registry Run Key',
          key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          value: 'UpdatePDFService',
          data: 'C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe',
          timestamp: '2024-01-15T14:25:00Z'
        }
      ];
    }

    if (artifacts.eventLogs.events > 0) {
      parsedData.timeline = [
        {
          timestamp: '2024-01-15T14:23:15Z',
          source: 'Security Event Log',
          eventId: 4688,
          description: 'Process Creation: PDFEditor.exe',
          details: 'New process created with PID 1234'
        },
        {
          timestamp: '2024-01-15T14:24:30Z',
          source: 'Security Event Log',
          eventId: 4688,
          description: 'Process Creation: powershell.exe',
          details: 'PowerShell execution with suspicious parameters'
        },
        {
          timestamp: '2024-01-15T14:25:42Z',
          source: 'Security Event Log',
          eventId: 4689,
          description: 'Process Termination: PDFEditor.exe',
          details: 'Process terminated with exit code 0'
        }
      ];
    }

    return parsedData;
  }

  /**
   * Correlate evidence across different artifact types
   */
  async correlateEvidence(parsedArtifacts) {
    const correlations = {
      timelineEvents: [],
      suspiciousActivities: [],
      attackChain: []
    };

    // Cross-reference execution with registry modifications
    const pdfEditorExecution = parsedArtifacts.executedProcesses.find(p => 
      p.name === 'PDFEditor.exe'
    );

    const registryPersistence = parsedArtifacts.persistenceMechanisms.find(p => 
      p.type === 'Registry Run Key'
    );

    if (pdfEditorExecution && registryPersistence) {
      correlations.attackChain.push({
        stage: 'Initial Access + Persistence',
        description: 'PDF editor execution followed by registry persistence',
        timeframe: `${pdfEditorExecution.firstRun} to ${registryPersistence.timestamp}`,
        confidence: 'High',
        mitre: ['T1566.001', 'T1547.001']
      });
    }

    // Timeline correlation
    correlations.timelineEvents = parsedArtifacts.timeline.sort((a, b) => 
      new Date(a.timestamp) - new Date(b.timestamp)
    );

    // Identify suspicious patterns
    const powerShellExecution = parsedArtifacts.executedProcesses.find(p => 
      p.name === 'powershell.exe' && p.commandLine?.includes('ExecutionPolicy Bypass')
    );

    if (powerShellExecution) {
      correlations.suspiciousActivities.push({
        type: 'Defense Evasion',
        description: 'PowerShell execution with bypassed execution policy',
        evidence: powerShellExecution.commandLine,
        risk: 'High',
        mitre: 'T1059.001'
      });
    }

    return correlations;
  }

  /**
   * Generate AI investigation report
   */
  async generateReport(correlatedEvidence, caseDescription) {
    const investigationContext = this.buildInvestigationContext(correlatedEvidence, caseDescription);
    
    const prompt = `
      As a senior DFIR investigator, analyze the following Windows forensic evidence and provide a comprehensive investigation report.

      Case Description: ${caseDescription}

      Evidence Analysis:
      ${JSON.stringify(investigationContext, null, 2)}

      Provide a structured report with:
      1. Executive Summary
      2. Key Findings (with MITRE ATT&CK mapping)
      3. Attack Timeline
      4. Indicators of Compromise
      5. Recommendations

      Focus on evidence-based conclusions. If data is insufficient, state so clearly.
      Include specific timestamps, file paths, and registry keys where available.
    `;

    try {
      const aiResponse = await this.aiModel.generate({
        prompt,
        temperature: 0.1,
        maxTokens: 4000
      });

      // Parse AI response and structure it
      return this.parseAIReport(aiResponse, correlatedEvidence);

    } catch (error) {
      console.error('AI report generation failed:', error);
      // Fallback to template-based report
      return this.generateFallbackReport(correlatedEvidence, caseDescription);
    }
  }

  /**
   * Build investigation context for AI analysis
   */
  buildInvestigationContext(correlatedEvidence) {
    return {
      timeline: correlatedEvidence.timelineEvents,
      executedProcesses: correlatedEvidence.suspiciousActivities,
      attackChain: correlatedEvidence.attackChain,
      riskAssessment: this.calculateRiskLevel(correlatedEvidence)
    };
  }

  /**
   * Parse AI response into structured report
   */
  parseAIReport(aiResponse, evidence) {
    // In a real implementation, this would parse the AI response
    // For now, return a structured template with enhanced data
    
    const severityMapping = {
      'High': 'high',
      'Medium': 'medium', 
      'Low': 'low',
      'Critical': 'critical'
    };

    return {
      caseId: `CASE-${Date.now()}`,
      timestamp: new Date().toISOString(),
      summary: 'AI analysis detected potential malware execution with persistence mechanisms. The attack chain shows initial access via a suspicious PDF editor download, followed by PowerShell execution and registry-based persistence.',
      findings: [
        {
          category: 'Initial Access',
          severity: 'High',
          description: 'Suspicious PDF editor (PDFEditor.exe) was downloaded and executed from user Downloads folder',
          evidence: 'Prefetch analysis, Process execution timeline (Event ID 4688)',
          mitre: 'T1566.001',
          timestamp: '2024-01-15T14:23:15Z'
        },
        {
          category: 'Execution',
          severity: 'Critical',
          description: 'PowerShell executed with bypassed execution policy, indicating potential malicious script execution',
          evidence: 'Event Log 4688, Command line: -ExecutionPolicy Bypass -File C:\\temp\\update.ps1',
          mitre: 'T1059.001',
          timestamp: '2024-01-15T14:24:30Z'
        },
        {
          category: 'Persistence',
          severity: 'High',
          description: 'Registry Run key created for automatic startup of suspicious executable',
          evidence: 'Registry analysis: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdatePDFService',
          mitre: 'T1547.001',
          timestamp: '2024-01-15T14:25:00Z'
        },
        {
          category: 'Defense Evasion',
          severity: 'High',
          description: 'Original malware executable self-deleted after establishing persistence',
          evidence: 'File system timeline analysis, MFT records showing deletion',
          mitre: 'T1070.004',
          timestamp: '2024-01-15T14:25:42Z'
        }
      ],
      indicators: [
        'PDFEditor.exe (SHA256: a1b2c3d4e5f6789...)',
        'C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe',
        'Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdatePDFService',
        'PowerShell script: C:\\temp\\update.ps1',
        'Process execution pattern: PDF -> PowerShell -> Persistence'
      ],
      recommendations: [
        'Immediately isolate the affected system from the network',
        'Search for additional instances of UpdatePDFService across the environment',
        'Check for C:\\temp\\update.ps1 and analyze its contents if present',
        'Review email logs for the initial PDF editor download source',
        'Update EDR rules to detect similar PowerShell execution patterns',
        'Implement application whitelisting to prevent unauthorized executable execution',
        'Conduct memory analysis if system is still running to identify additional artifacts'
      ],
      attackChain: evidence.attackChain || [],
      confidence: 'High'
    };
  }

  /**
   * Generate fallback report if AI fails
   */
  generateFallbackReport(evidence, caseDescription) {
    return {
      caseId: `CASE-${Date.now()}`,
      timestamp: new Date().toISOString(),
      summary: 'Manual analysis detected suspicious activity based on artifact correlation. Further investigation recommended.',
      findings: [
        {
          category: 'Analysis Notice',
          severity: 'Medium',
          description: 'AI analysis temporarily unavailable. Manual correlation detected potential threats.',
          evidence: 'Automated artifact parsing and correlation',
          mitre: 'N/A'
        }
      ],
      indicators: ['Manual review required'],
      recommendations: [
        'Review uploaded artifacts manually',
        'Run detailed timeline analysis',
        'Consult with senior DFIR analyst'
      ]
    };
  }

  /**
   * Calculate overall risk level
   */
  calculateRiskLevel(evidence) {
    let riskScore = 0;
    
    if (evidence.suspiciousActivities.length > 0) riskScore += 30;
    if (evidence.attackChain.length > 0) riskScore += 40;
    if (evidence.timelineEvents.length > 5) riskScore += 20;
    
    if (riskScore >= 70) return 'Critical';
    if (riskScore >= 50) return 'High';
    if (riskScore >= 30) return 'Medium';
    return 'Low';
  }
}

export default new InvestigationAPI();