import React from 'react';

const StatusBar = ({ uploadedFiles, isAnalyzing, progress }) => {
  const getStatusMessage = () => {
    if (isAnalyzing) {
      return `Analyzing evidence... ${progress}%`;
    }
    if (uploadedFiles > 0) {
      return `${uploadedFiles} evidence files loaded`;
    }
    return 'Ready for evidence upload';
  };

  return (
    <div className="status-bar">
      <div className="status-left">
        <div className="status-item">
          <span className={`status-dot ${isAnalyzing ? 'analyzing' : ''}`}></span>
          <span>{getStatusMessage()}</span>
        </div>
        {isAnalyzing && (
          <div className="progress-bar" style={{ width: '200px' }}>
            <div 
              className="progress-fill" 
              style={{ width: `${progress}%` }}
            ></div>
          </div>
        )}
      </div>
      
      <div className="status-right">
        <div className="status-item">
          <span>v1.0.0</span>
        </div>
        <div className="status-item">
          <span>{new Date().toLocaleTimeString()}</span>
        </div>
      </div>
    </div>
  );
};

export default StatusBar;