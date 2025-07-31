import React from 'react';

const Header = ({ onLoadDemo }) => {
  return (
    <header className="header">
      <div className="header-title">
        <div className="header-icon">
          🔍
        </div>
        <h1>IRHunter</h1>
        <span className="header-subtitle">Windows Artifact Investigator</span>
      </div>
      
      <div className="header-actions">
        <div className="status-item">
          <span className="status-dot"></span>
          <span>System Ready</span>
        </div>
        <button className="btn btn-primary" onClick={onLoadDemo}>
          🎮 Load Demo
        </button>
        <button className="btn btn-secondary">
          Settings
        </button>
      </div>
    </header>
  );
};

export default Header;