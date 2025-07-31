import React, { useState, useRef } from 'react';
import UploadPanel from './components/UploadPanel';
import InvestigationPanel from './components/InvestigationPanel';
import CasePromptBar from './components/CasePromptBar';
import Header from './components/Header';
import StatusBar from './components/StatusBar';
import investigationAPI from './api/investigation';
import { demoFiles, demoCase, demoReport, demoArtifacts } from './demo/DemoData';
import './styles/App.css';

function App() {
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [caseDescription, setCaseDescription] = useState('');
  const [investigationReport, setInvestigationReport] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [extractedArtifacts, setExtractedArtifacts] = useState({});
  
  const investigationPanelRef = useRef(null);

  const handleFilesUploaded = (files) => {
    setUploadedFiles(files);
    setInvestigationReport(null);
  };

  const handleStartInvestigation = async () => {
    if (uploadedFiles.length === 0) {
      alert('Please upload forensic evidence files first.');
      return;
    }
    
    if (!caseDescription.trim()) {
      alert('Please provide a case description to guide the investigation.');
      return;
    }

    setIsAnalyzing(true);
    setAnalysisProgress(0);
    
    try {
      // Perform AI-driven investigation
      const report = await performInvestigation();
      setInvestigationReport(report);
      
      // Scroll to investigation panel
      if (investigationPanelRef.current) {
        investigationPanelRef.current.scrollIntoView({ behavior: 'smooth' });
      }
      
    } catch (error) {
      console.error('Investigation failed:', error);
      alert('Investigation failed: ' + error.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const performInvestigation = async () => {
    try {
      const result = await investigationAPI.analyzeEvidence(
        uploadedFiles, 
        caseDescription, 
        setAnalysisProgress
      );
      
      setExtractedArtifacts(result.artifacts);
      return result.report;
      
    } catch (error) {
      console.error('Investigation failed:', error);
      throw error;
    }
  };

  const handleLoadDemo = () => {
    setUploadedFiles(demoFiles);
    setCaseDescription(demoCase);
    setExtractedArtifacts(demoArtifacts);
    setInvestigationReport(demoReport);
    
    // Scroll to investigation panel
    if (investigationPanelRef.current) {
      setTimeout(() => {
        investigationPanelRef.current.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }
  };

      return (
      <div className="app">
        <Header onLoadDemo={handleLoadDemo} />
      
      <div className="main-container">
        <div className="left-panel">
          <UploadPanel 
            onFilesUploaded={handleFilesUploaded}
            uploadedFiles={uploadedFiles}
          />
        </div>
        
        <div className="center-panel">
          <InvestigationPanel 
            ref={investigationPanelRef}
            report={investigationReport}
            isAnalyzing={isAnalyzing}
            progress={analysisProgress}
            extractedArtifacts={extractedArtifacts}
            onStartInvestigation={handleStartInvestigation}
            hasFiles={uploadedFiles.length > 0}
          />
        </div>
        
        <div className="right-panel">
          <CasePromptBar 
            value={caseDescription}
            onChange={setCaseDescription}
            onSubmit={handleStartInvestigation}
            isAnalyzing={isAnalyzing}
          />
        </div>
      </div>
      
      <StatusBar 
        uploadedFiles={uploadedFiles.length}
        isAnalyzing={isAnalyzing}
        progress={analysisProgress}
      />
    </div>
  );
}

export default App;