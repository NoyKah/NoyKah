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
              Incident Summary
            </label>
            <textarea
              className="form-textarea case-input"
              placeholder="Describe the incident to guide the AI investigation...

Examples:
• Employee downloaded suspicious PDF editor from unknown site; malware self-deleted after execution
• User clicked on email attachment, system started behaving slowly
• EDR alert triggered by PowerShell execution
• Suspicious network traffic detected to unknown IP

Be specific about:
- Initial vector (email, download, USB, etc.)
- Suspicious files or processes
- Timeline of events
- User actions
- EDR/AV alerts"
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
                  🔍 Start Investigation
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