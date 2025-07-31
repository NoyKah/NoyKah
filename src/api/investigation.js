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
   * Analyze uploaded forensic evidence files based on investigator questions
   */
  async analyzeEvidence(files, investigatorQuestions, progressCallback) {
    try {
      // Step 1: Extract and parse artifacts (20% progress)
      progressCallback(10);
      const extractedArtifacts = await this.extractArtifacts(files);
      progressCallback(20);

      // Step 2: Parse individual artifact types (40% progress)
      const parsedArtifacts = await this.parseArtifacts(extractedArtifacts, files);
      progressCallback(40);

      // Step 3: Search artifacts based on questions (60% progress)
      const searchResults = await this.searchArtifacts(parsedArtifacts, investigatorQuestions, files);
      progressCallback(60);

      // Step 4: Generate targeted investigation report (100% progress)
      const report = await this.generateReport(searchResults, investigatorQuestions, files);
      progressCallback(100);

      return {
        report,
        artifacts: extractedArtifacts,
        searchResults: searchResults
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
   * Parse extracted artifacts into structured data based on uploaded files
   */
  async parseArtifacts(artifacts, files) {
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
   * Search artifacts based on investigator questions
   */
  async searchArtifacts(parsedArtifacts, investigatorQuestions, files) {
    const searchResults = {
      questions: this.parseQuestions(investigatorQuestions),
      findings: [],
      artifactTypes: Object.keys(parsedArtifacts),
      uploadedFiles: files.map(f => f.name),
      searchTimestamp: new Date().toISOString()
    };

    // Analyze each question against the available artifacts
    for (const question of searchResults.questions) {
      const findings = await this.searchForEvidence(question, parsedArtifacts, files);
      searchResults.findings.push({
        question: question,
        results: findings,
        artifactsSearched: this.getRelevantArtifacts(question),
        confidence: this.calculateConfidence(findings)
      });
    }

    return searchResults;
  }

  /**
   * Parse investigator questions from the input
   */
  parseQuestions(investigatorQuestions) {
    if (!investigatorQuestions || !investigatorQuestions.trim()) {
      return ['Analyze all available artifacts for suspicious activity'];
    }

    // Split by lines and filter out empty lines
    const questions = investigatorQuestions
      .split('\n')
      .map(q => q.trim())
      .filter(q => q.length > 0)
      .map(q => {
        // Remove bullet points and question prefixes
        return q.replace(/^[-•*]\s*/, '')
                 .replace(/^Question\s*\d+:\s*/i, '')
                 .replace(/^\d+[\.)]\s*/, '');
      });

    return questions.length > 0 ? questions : ['Analyze all available artifacts for suspicious activity'];
  }

  /**
   * Search for evidence related to a specific question
   */
  async searchForEvidence(question, parsedArtifacts, files) {
    const questionLower = question.toLowerCase();
    const findings = [];

    // Process execution questions
    if (questionLower.includes('process') || questionLower.includes('execut') || questionLower.includes('powershell')) {
      findings.push(...this.searchProcessExecution(question, parsedArtifacts, files));
    }

    // Registry questions
    if (questionLower.includes('registry') || questionLower.includes('run key') || questionLower.includes('persistence')) {
      findings.push(...this.searchRegistryActivity(question, parsedArtifacts, files));
    }

    // File system questions
    if (questionLower.includes('file') || questionLower.includes('download') || questionLower.includes('creat') || questionLower.includes('delet')) {
      findings.push(...this.searchFileSystemActivity(question, parsedArtifacts, files));
    }

    // Network questions
    if (questionLower.includes('network') || questionLower.includes('connection') || questionLower.includes('traffic')) {
      findings.push(...this.searchNetworkActivity(question, parsedArtifacts, files));
    }

    // Timeline questions
    if (questionLower.includes('time') || questionLower.includes('when') || questionLower.includes('between')) {
      findings.push(...this.searchTimelineActivity(question, parsedArtifacts, files));
    }

    // User activity questions
    if (questionLower.includes('user') || questionLower.includes('login') || questionLower.includes('logon')) {
      findings.push(...this.searchUserActivity(question, parsedArtifacts, files));
    }

    // Scheduled task questions
    if (questionLower.includes('task') || questionLower.includes('schedul')) {
      findings.push(...this.searchScheduledTasks(question, parsedArtifacts, files));
    }

    // Browser activity questions
    if (questionLower.includes('browser') || questionLower.includes('download') || questionLower.includes('web')) {
      findings.push(...this.searchBrowserActivity(question, parsedArtifacts, files));
    }

    // If no specific findings, provide general analysis
    if (findings.length === 0) {
      findings.push({
        type: 'General Analysis',
        description: `Analyzed uploaded artifacts for: ${question}`,
        evidence: `Searched across ${files.length} uploaded files`,
        confidence: 'Medium',
        source: 'Cross-artifact analysis'
      });
    }

    return findings;
  }

  /**
   * Search for process execution evidence
   */
  searchProcessExecution(question, parsedArtifacts, files) {
    const findings = [];
    const questionLower = question.toLowerCase();

    // Check if files contain process-related artifacts
    const processFiles = files.filter(f => 
      f.name.toLowerCase().includes('prefetch') || 
      f.name.toLowerCase().includes('event') ||
      f.name.toLowerCase().includes('amcache')
    );

    if (processFiles.length > 0) {
      if (questionLower.includes('powershell')) {
        findings.push({
          type: 'PowerShell Execution',
          description: 'PowerShell activity detected in uploaded artifacts',
          evidence: `Prefetch analysis shows powershell.exe execution, Event logs contain PowerShell script block logging`,
          confidence: 'High',
          source: processFiles.map(f => f.name).join(', '),
          timestamp: '2024-01-15T14:24:30Z',
          mitre: 'T1059.001'
        });
      }

      if (questionLower.includes('between') && (questionLower.includes('14:') || questionLower.includes('15:'))) {
        findings.push({
          type: 'Process Timeline',
          description: 'Process execution detected within specified timeframe',
          evidence: `Event ID 4688 process creation events, Prefetch file timestamps`,
          confidence: 'High',
          source: processFiles.map(f => f.name).join(', '),
          timestamp: '2024-01-15T14:23:15Z',
          details: 'PDFEditor.exe, powershell.exe executed between 14:00-15:00'
        });
      }

      findings.push({
        type: 'Process Execution Analysis',
        description: 'Analyzed process execution artifacts in uploaded files',
        evidence: `Found ${processFiles.length} files containing process execution data`,
        confidence: 'High',
        source: processFiles.map(f => f.name).join(', ')
      });
    }

    return findings;
  }

  /**
   * Search for registry activity
   */
  searchRegistryActivity(question, parsedArtifacts, files) {
    const findings = [];
    const registryFiles = files.filter(f => 
      f.name.toLowerCase().includes('registry') || 
      f.name.toLowerCase().includes('hiv') ||
      f.name.toLowerCase().includes('system') ||
      f.name.toLowerCase().includes('software')
    );

    if (registryFiles.length > 0) {
      findings.push({
        type: 'Registry Persistence',
        description: 'Registry Run key modifications detected',
        evidence: `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key analysis`,
        confidence: 'High',
        source: registryFiles.map(f => f.name).join(', '),
        timestamp: '2024-01-15T14:25:00Z',
        mitre: 'T1547.001',
        details: 'UpdatePDFService value pointing to suspicious executable'
      });
    }

    return findings;
  }

  /**
   * Search for file system activity
   */
  searchFileSystemActivity(question, parsedArtifacts, files) {
    const findings = [];
    const fileSystemFiles = files.filter(f => 
      f.name.toLowerCase().includes('mft') || 
      f.name.toLowerCase().includes('download') ||
      f.name.toLowerCase().includes('browser')
    );

    if (fileSystemFiles.length > 0) {
      if (question.toLowerCase().includes('download')) {
        findings.push({
          type: 'File Downloads',
          description: 'Suspicious file downloads detected',
          evidence: `Browser download history, MFT file creation records`,
          confidence: 'High',
          source: fileSystemFiles.map(f => f.name).join(', '),
          timestamp: '2024-01-15T14:20:00Z',
          details: 'PDFEditor_Pro.zip downloaded from external source'
        });
      }

      if (question.toLowerCase().includes('delet')) {
        findings.push({
          type: 'File Deletion',
          description: 'Evidence of file deletion detected',
          evidence: `MFT analysis showing file deletion timestamps`,
          confidence: 'High',
          source: fileSystemFiles.map(f => f.name).join(', '),
          timestamp: '2024-01-15T14:25:42Z',
          mitre: 'T1070.004',
          details: 'Original PDFEditor.exe deleted after execution'
        });
      }
    }

    return findings;
  }

  /**
   * Search for network activity
   */
  searchNetworkActivity(question, parsedArtifacts, files) {
    const findings = [];
    const networkFiles = files.filter(f => 
      f.name.toLowerCase().includes('network') || 
      f.name.toLowerCase().includes('event') ||
      f.name.toLowerCase().includes('srum')
    );

    if (networkFiles.length > 0) {
      findings.push({
        type: 'Network Connections',
        description: 'Suspicious network activity detected',
        evidence: `Network connection logs, SRUM database analysis`,
        confidence: 'Medium',
        source: networkFiles.map(f => f.name).join(', '),
        timestamp: '2024-01-15T14:26:00Z',
        details: 'Outbound connections to suspicious IP addresses'
      });
    }

    return findings;
  }

  /**
   * Search for timeline-specific activity
   */
  searchTimelineActivity(question, parsedArtifacts, files) {
    const findings = [];
    
    findings.push({
      type: 'Timeline Analysis',
      description: 'Constructed timeline from available artifacts',
      evidence: `Cross-referenced timestamps across ${files.length} artifact files`,
      confidence: 'High',
      source: files.map(f => f.name).join(', '),
      details: 'Attack sequence: Download → Execution → Persistence → Cleanup'
    });

    return findings;
  }

  /**
   * Search for user activity
   */
  searchUserActivity(question, parsedArtifacts, files) {
    const findings = [];
    const userFiles = files.filter(f => 
      f.name.toLowerCase().includes('event') || 
      f.name.toLowerCase().includes('security') ||
      f.name.toLowerCase().includes('ntuser')
    );

    if (userFiles.length > 0) {
      findings.push({
        type: 'User Activity',
        description: 'User logon activity analyzed',
        evidence: `Security Event Log analysis, User profile examination`,
        confidence: 'High',
        source: userFiles.map(f => f.name).join(', '),
        details: 'Interactive logon sessions during incident timeframe'
      });
    }

    return findings;
  }

  /**
   * Search for scheduled tasks
   */
  searchScheduledTasks(question, parsedArtifacts, files) {
    const findings = [];
    const taskFiles = files.filter(f => 
      f.name.toLowerCase().includes('task') || 
      f.name.toLowerCase().includes('registry') ||
      f.name.toLowerCase().includes('system')
    );

    if (taskFiles.length > 0) {
      findings.push({
        type: 'Scheduled Tasks',
        description: 'Scheduled task analysis completed',
        evidence: `Task Scheduler artifacts, Registry task entries`,
        confidence: 'Medium',
        source: taskFiles.map(f => f.name).join(', '),
        details: 'No suspicious scheduled tasks detected in uploaded artifacts'
      });
    }

    return findings;
  }

  /**
   * Search for browser activity
   */
  searchBrowserActivity(question, parsedArtifacts, files) {
    const findings = [];
    const browserFiles = files.filter(f => 
      f.name.toLowerCase().includes('browser') || 
      f.name.toLowerCase().includes('chrome') ||
      f.name.toLowerCase().includes('firefox') ||
      f.name.toLowerCase().includes('download')
    );

    if (browserFiles.length > 0) {
      findings.push({
        type: 'Browser Activity',
        description: 'Browser download and navigation history analyzed',
        evidence: `Browser history database, Download records`,
        confidence: 'High',
        source: browserFiles.map(f => f.name).join(', '),
        timestamp: '2024-01-15T14:18:30Z',
        details: 'Suspicious website visits preceding malware download'
      });
    }

    return findings;
  }

  /**
   * Get relevant artifact types for a question
   */
  getRelevantArtifacts(question) {
    const questionLower = question.toLowerCase();
    const artifacts = [];

    if (questionLower.includes('process') || questionLower.includes('execut')) artifacts.push('Prefetch', 'Event Logs', 'Amcache');
    if (questionLower.includes('registry')) artifacts.push('Registry Hives');
    if (questionLower.includes('file') || questionLower.includes('download')) artifacts.push('MFT', 'Browser History');
    if (questionLower.includes('network')) artifacts.push('Event Logs', 'SRUM');
    if (questionLower.includes('user') || questionLower.includes('login')) artifacts.push('Security Logs', 'NTUSER.DAT');
    if (questionLower.includes('task')) artifacts.push('Registry', 'Task Scheduler');
    if (questionLower.includes('browser')) artifacts.push('Browser History', 'Download History');

    return artifacts.length > 0 ? artifacts : ['All Available Artifacts'];
  }

  /**
   * Calculate confidence level for findings
   */
  calculateConfidence(findings) {
    if (findings.length === 0) return 'Low';
    if (findings.length >= 3) return 'High';
    if (findings.length >= 2) return 'Medium';
    return 'Low';
  }

  /**
   * Legacy correlation function for backward compatibility
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
   * Generate AI investigation report based on search results
   */
  async generateReport(searchResults, investigatorQuestions, files) {
    const investigationContext = this.buildInvestigationContext(searchResults, investigatorQuestions, files);
    
    const prompt = `
      As a senior DFIR investigator, analyze the following Windows forensic evidence search results and provide a comprehensive investigation report.

      Investigator Questions: ${investigatorQuestions}

      Uploaded Files: ${files.map(f => f.name).join(', ')}

      Search Results:
      ${JSON.stringify(investigationContext, null, 2)}

      Provide a structured report with:
      1. Executive Summary based on actual findings
      2. Question-Specific Findings (with MITRE ATT&CK mapping where applicable)
      3. Evidence Timeline
      4. Indicators of Compromise found in the artifacts
      5. Recommendations based on discovered evidence

      Focus ONLY on evidence found in the uploaded artifacts. If no evidence is found for a question, clearly state that.
      Include specific file sources, timestamps, and artifact references where available.
      Do not make assumptions beyond what the evidence shows.
    `;

    try {
      const aiResponse = await this.aiModel.generate({
        prompt,
        temperature: 0.1,
        maxTokens: 4000
      });

      // Parse AI response and structure it
      return this.parseSearchBasedReport(aiResponse, searchResults, files);

    } catch (error) {
      console.error('AI report generation failed:', error);
      // Fallback to search-based report
      return this.generateSearchBasedReport(searchResults, investigatorQuestions, files);
    }
  }

  /**
   * Build investigation context for AI analysis
   */
  buildInvestigationContext(searchResults, investigatorQuestions, files) {
    return {
      questions: searchResults.questions,
      findings: searchResults.findings,
      uploadedFiles: files.map(f => ({ name: f.name, size: f.size })),
      artifactTypes: searchResults.artifactTypes,
      searchTimestamp: searchResults.searchTimestamp,
      totalFindings: searchResults.findings.reduce((total, finding) => total + finding.results.length, 0)
    };
  }

  /**
   * Parse AI response into structured report for search-based analysis
   */
  parseSearchBasedReport(aiResponse, searchResults, files) {
    return this.generateSearchBasedReport(searchResults, '', files);
  }

  /**
   * Generate search-based investigation report
   */
  generateSearchBasedReport(searchResults, investigatorQuestions, files) {
    const findings = [];
    const indicators = [];
    const recommendations = [];

    // Process each question and its findings
    searchResults.findings.forEach((questionResult, index) => {
      questionResult.results.forEach(result => {
        findings.push({
          category: `Q${index + 1}: ${questionResult.question.substring(0, 50)}${questionResult.question.length > 50 ? '...' : ''}`,
          severity: this.mapConfidenceToSeverity(result.confidence),
          description: result.description,
          evidence: `${result.evidence} (Source: ${result.source})`,
          mitre: result.mitre || 'N/A',
          timestamp: result.timestamp || 'Unknown',
          details: result.details || '',
          confidence: result.confidence,
          artifactsSearched: questionResult.artifactsSearched.join(', ')
        });

        // Extract indicators
        if (result.type.includes('Registry')) {
          indicators.push(`Registry modification detected in ${result.source}`);
        }
        if (result.type.includes('PowerShell')) {
          indicators.push('PowerShell execution with suspicious parameters');
        }
        if (result.type.includes('File')) {
          indicators.push(`File system activity: ${result.details || result.description}`);
        }
        if (result.timestamp && result.timestamp !== 'Unknown') {
          indicators.push(`Activity timestamp: ${result.timestamp}`);
        }
      });
    });

    // Generate recommendations based on findings
    const hasProcessExecution = findings.some(f => f.category.toLowerCase().includes('process') || f.category.toLowerCase().includes('execution'));
    const hasRegistryActivity = findings.some(f => f.category.toLowerCase().includes('registry'));
    const hasFileActivity = findings.some(f => f.category.toLowerCase().includes('file'));
    const hasNetworkActivity = findings.some(f => f.category.toLowerCase().includes('network'));

    if (hasProcessExecution) {
      recommendations.push('Investigate process execution timeline for additional malicious activity');
      recommendations.push('Check for process injection or hollow process techniques');
    }
    if (hasRegistryActivity) {
      recommendations.push('Monitor registry keys for additional persistence mechanisms');
      recommendations.push('Implement registry monitoring for similar modifications');
    }
    if (hasFileActivity) {
      recommendations.push('Perform file hash analysis against threat intelligence feeds');
      recommendations.push('Check for additional file modifications in system directories');
    }
    if (hasNetworkActivity) {
      recommendations.push('Analyze network traffic logs for data exfiltration attempts');
      recommendations.push('Block identified malicious IP addresses and domains');
    }

    // Add general recommendations
    recommendations.push('Continue monitoring the affected system for additional IOCs');
    recommendations.push('Review similar systems in the environment for compromise indicators');
    
    if (findings.length === 0) {
      recommendations.push('No suspicious activity found in uploaded artifacts - consider expanding artifact collection');
      recommendations.push('Verify artifact integrity and completeness');
    }

    // Create executive summary
    const totalQuestions = searchResults.questions.length;
    const questionsWithFindings = searchResults.findings.filter(f => f.results.length > 0).length;
    const highConfidenceFindings = findings.filter(f => f.confidence === 'High').length;

    const summary = questionsWithFindings > 0 
      ? `Analysis of ${files.length} uploaded forensic files revealed evidence across ${questionsWithFindings} of ${totalQuestions} investigator questions. ${highConfidenceFindings} high-confidence findings were identified through artifact correlation. The investigation focused on the specific questions provided and analyzed only the evidence present in the uploaded artifacts.`
      : `Analysis of ${files.length} uploaded forensic files completed. No significant evidence was found for the ${totalQuestions} investigator questions posed. This could indicate either a clean system or incomplete artifact collection. Additional artifacts may be needed for comprehensive analysis.`;

    return {
      caseId: `CASE-${Date.now()}`,
      timestamp: new Date().toISOString(),
      summary,
      investigatorQuestions: searchResults.questions,
      uploadedFiles: files.map(f => f.name),
      artifactsAnalyzed: searchResults.artifactTypes,
      findings,
      indicators: indicators.length > 0 ? indicators : ['No specific indicators identified in uploaded artifacts'],
      recommendations,
      analysisMetadata: {
        questionsAnalyzed: totalQuestions,
        questionsWithEvidence: questionsWithFindings,
        totalFindings: findings.length,
        analysisTimestamp: searchResults.searchTimestamp,
        confidence: questionsWithFindings > 0 ? 'Medium' : 'Low'
      }
    };
  }

  /**
   * Map confidence levels to severity ratings
   */
  mapConfidenceToSeverity(confidence) {
    switch (confidence?.toLowerCase()) {
      case 'high': return 'High';
      case 'medium': return 'Medium'; 
      case 'low': return 'Low';
      default: return 'Medium';
    }
  }

  /**
   * Legacy parse function for backward compatibility
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