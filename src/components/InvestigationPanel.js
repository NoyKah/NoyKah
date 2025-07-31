import React, { forwardRef } from 'react';
import pdfExporter from '../utils/pdfExport';
import './InvestigationPanel.css';

const InvestigationPanel = forwardRef(({ 
  report, 
  isAnalyzing, 
  progress, 
  extractedArtifacts, 
  onStartInvestigation, 
  hasFiles 
}, ref) => {

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'status-critical';
      case 'high': return 'status-high';
      case 'medium': return 'status-medium';
      case 'low': return 'status-low';
      default: return 'status-medium';
    }
  };

  const exportToPDF = async () => {
    try {
      await pdfExporter.exportReportFallback(report);
    } catch (error) {
      console.error('PDF export failed:', error);
      alert('PDF export failed. Please try again.');
    }
  };

  if (isAnalyzing) {
    return (
      <div ref={ref} className="investigation-panel">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">🔍 AI Investigation in Progress</h2>
            <div className="analysis-progress">
              <span>{progress}%</span>
            </div>
          </div>
          
          <div className="analysis-status">
            <div className="progress-bar mb-2">
              <div 
                className="progress-fill" 
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            
            <div className="analysis-steps">
              <div className={`analysis-step ${progress >= 20 ? 'completed' : 'active'}`}>
                <span className="step-icon">📦</span>
                <span>Extracting & Parsing Artifacts</span>
              </div>
              <div className={`analysis-step ${progress >= 50 ? 'completed' : progress >= 20 ? 'active' : ''}`}>
                <span className="step-icon">🔗</span>
                <span>Correlating Evidence</span>
              </div>
              <div className={`analysis-step ${progress >= 80 ? 'completed' : progress >= 50 ? 'active' : ''}`}>
                <span className="step-icon">🧠</span>
                <span>Generating Investigation Report</span>
              </div>
              <div className={`analysis-step ${progress >= 100 ? 'completed' : progress >= 80 ? 'active' : ''}`}>
                <span className="step-icon">📋</span>
                <span>Finalizing Analysis</span>
              </div>
            </div>

            {Object.keys(extractedArtifacts).length > 0 && (
              <div className="artifact-summary">
                <h4>Extracted Artifacts</h4>
                <div className="artifact-grid">
                  {Object.entries(extractedArtifacts).map(([type, data]) => (
                    <div key={type} className="artifact-item">
                      <span className="artifact-type">{type}</span>
                      <span className="artifact-count">
                        {typeof data === 'object' ? Object.values(data)[0] : data} items
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div ref={ref} className="investigation-panel">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">🔍 IRHunter Investigation Console</h2>
          </div>
          
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <h3>Ready to Begin Investigation</h3>
            <p>
              Upload your Windows forensic triage data and provide a case description 
              to start the AI-driven investigation.
            </p>
            
            <div className="getting-started">
              <h4>Getting Started:</h4>
              <ol>
                <li>Upload forensic evidence files (.zip, .rar, .7z, .tar)</li>
                <li>Provide incident description in the case prompt</li>
                <li>Click "Start Investigation" to begin analysis</li>
              </ol>
            </div>

            {hasFiles && (
              <button 
                className="btn btn-primary"
                onClick={onStartInvestigation}
              >
                🚀 Ready to Start Investigation
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div ref={ref} className="investigation-panel">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">📋 Investigation Report</h2>
            <p className="report-meta">
              Case ID: <span className="mono">{report.caseId}</span> | 
              Generated: {new Date(report.timestamp).toLocaleString()}
            </p>
          </div>
          <button className="btn btn-secondary" onClick={exportToPDF}>
            📄 Export PDF
          </button>
        </div>

        <div className="report-content">
          <div className="report-summary">
            <h3>Executive Summary</h3>
            <p>{report.summary}</p>
          </div>

          <div className="report-findings">
            <h3>Investigation Findings</h3>
            {report.findings.map((finding, index) => (
              <div key={index} className="finding-item">
                <div className="finding-header">
                  <h4>{finding.category}</h4>
                  <span className={`status-indicator ${getSeverityColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </div>
                <p className="finding-description">{finding.description}</p>
                <div className="finding-evidence">
                  <strong>Evidence:</strong> 
                  <span className="mono">{finding.evidence}</span>
                </div>
                {finding.mitre && (
                  <div className="finding-mitre">
                    <strong>MITRE ATT&CK:</strong> 
                    <span className="mitre-id">{finding.mitre}</span>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="report-indicators">
            <h3>Indicators of Compromise (IoCs)</h3>
            <div className="ioc-list">
              {report.indicators.map((ioc, index) => (
                <div key={index} className="ioc-item mono">
                  {ioc}
                </div>
              ))}
            </div>
          </div>

          <div className="report-recommendations">
            <h3>Recommendations</h3>
            <ul>
              {report.recommendations.map((rec, index) => (
                <li key={index}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
});

InvestigationPanel.displayName = 'InvestigationPanel';

export default InvestigationPanel;