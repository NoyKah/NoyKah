import React from 'react';
import './CasePromptBar.css';

const CasePromptBar = ({ value, onChange, onSubmit, isAnalyzing }) => {
  const handleSubmit = (e) => {
    e.preventDefault();
    if (value.trim() && !isAnalyzing) {
      onSubmit();
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      handleSubmit(e);
    }
  };

  return (
    <div className="case-prompt-bar">
      <div className="card h-100">
        <div className="card-header">
          <h3 className="card-title">Case Description</h3>
          <span className="prompt-hint">Ctrl+Enter to analyze</span>
        </div>

        <form onSubmit={handleSubmit} className="prompt-form">
          <div className="form-group">
            <label className="form-label">
              Investigator Questions
            </label>
            <textarea
              className="form-textarea case-input"
              placeholder="Ask IRHunter specific questions about the uploaded artifacts...

Example Questions:
• What processes were executed between 14:00 and 15:00?
• Find evidence of PowerShell execution with bypassed policies
• Show me all registry modifications in the last 24 hours
• What files were created in the Downloads folder?
• Are there any suspicious network connections?
• Find evidence of persistence mechanisms
• What scheduled tasks were created recently?
• Show me browser download history for malicious files
• Find evidence of file deletion or anti-forensics
• What users logged in during the incident timeframe?

Multiple Questions (separate with line breaks):
- Question 1: Look for suspicious executable files
- Question 2: Find registry Run key modifications
- Question 3: Check for PowerShell script execution"
              value={value}
              onChange={(e) => onChange(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isAnalyzing}
              rows={20}
            />
          </div>

          <div className="prompt-actions">
            <button 
              type="submit" 
              className="btn btn-primary w-100"
              disabled={!value.trim() || isAnalyzing}
            >
              {isAnalyzing ? (
                <>
                  <span className="spin">⟳</span>
                  Analyzing...
                </>
              ) : (
                <>
                  🔍 Analyze Artifacts
                </>
              )}
            </button>
          </div>

          <div className="investigation-tips">
            <h4>Investigation Focus Areas</h4>
            <ul>
              <li><strong>Initial Access:</strong> Email attachments, downloads, removable media</li>
              <li><strong>Execution:</strong> Process execution, PowerShell, scripts</li>
              <li><strong>Persistence:</strong> Registry keys, scheduled tasks, services</li>
              <li><strong>Defense Evasion:</strong> File deletion, process injection</li>
              <li><strong>Discovery:</strong> System reconnaissance, file enumeration</li>
              <li><strong>Lateral Movement:</strong> Network shares, remote execution</li>
              <li><strong>Exfiltration:</strong> Network connections, data staging</li>
            </ul>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CasePromptBar;