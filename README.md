# 🔍 IRHunter - Windows Artifact Investigator

A professional AI-driven DFIR (Digital Forensics and Incident Response) investigation tool built with Base44. IRHunter is designed to analyze Windows forensic triage data and provide comprehensive investigation reports based on evidence correlation and AI analysis.

## 🎯 Features

### Core Capabilities
- **Large File Upload Support**: Upload forensic evidence up to 15GB
- **Multi-Format Support**: .zip, .rar, .7z, .tar archive formats
- **Password-Protected Archives**: Support for encrypted evidence files
- **AI-Driven Analysis**: 20+ years of DFIR expertise built into AI models
- **Professional Reporting**: Structured investigation reports with PDF export
- **Evidence Correlation**: Cross-reference multiple Windows artifacts

### Supported Windows Artifacts
- Registry Hives (SYSTEM, SOFTWARE, NTUSER.DAT)
- Event Logs (Security, System, Application)
- Prefetch Files (.pf)
- Amcache.hve
- SRUM Database
- MFT ($MFT)
- Browser History
- Scheduled Tasks
- Windows Services

### Investigation Framework
- MITRE ATT&CK Mapping
- Evidence-Based Conclusions
- Timeline Correlation
- IOC Extraction
- Professional Recommendations

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ 
- Base44 CLI (`npm install -g @base44/cli`)

### Installation

1. **Clone and Install**
   ```bash
   git clone <repository-url>
   cd irhunter-dfir-tool
   npm install
   ```

2. **Start Development Server**
   ```bash
   npm run dev
   ```

3. **Open IRHunter**
   - Navigate to `http://localhost:3000`
   - The application will open automatically

### Building for Production

```bash
npm run build
npm start
```

## 📋 Usage Guide

### 1. Upload Evidence
- **Left Panel**: Drag and drop or click to upload forensic files
- **Supported Formats**: .zip, .rar, .7z, .tar
- **Password Protection**: Enter password if archive is encrypted
- **File Size Limit**: 15GB maximum per upload

### 2. Describe the Incident
- **Right Panel**: Provide detailed case description
- **Be Specific**: Include initial vector, suspicious activities, timeline
- **Examples Provided**: Built-in templates for common scenarios

### 3. Start Investigation
- **AI Analysis**: Click "Start Investigation" to begin
- **Progress Tracking**: Real-time progress with artifact extraction details
- **Automatic Correlation**: Evidence correlation across multiple artifacts

### 4. Review Results
- **Structured Report**: Executive summary, findings, IOCs, recommendations
- **MITRE Mapping**: ATT&CK framework classification
- **Evidence Citations**: Specific timestamps and artifact references
- **PDF Export**: Professional report generation

## 🏗️ Architecture

### Frontend (React)
```
src/
├── components/           # React components
│   ├── UploadPanel.js   # File upload interface
│   ├── CasePromptBar.js # Incident description input
│   ├── InvestigationPanel.js # Report display
│   └── ...
├── api/                 # API integration
│   └── investigation.js # AI analysis logic
├── utils/               # Utilities
│   └── pdfExport.js    # PDF report generation
└── styles/              # CSS styling
```

### Base44 Integration
- **AI Models**: GPT-4 Turbo for analysis
- **Upload Handling**: Large file processing
- **Security**: CORS, rate limiting, input validation

### Investigation Pipeline
1. **Artifact Extraction**: Parse uploaded forensic data
2. **Evidence Parsing**: Extract structured data from artifacts
3. **Correlation Engine**: Cross-reference evidence across artifacts
4. **AI Analysis**: Generate investigation report with conclusions
5. **Report Export**: PDF generation with professional formatting

## 🔧 Configuration

### Base44 Configuration (`base44.config.js`)
```javascript
export default {
  upload: {
    maxFileSize: '15GB',
    allowedTypes: ['.zip', '.rar', '.7z', '.tar', '.gz']
  },
  ai: {
    model: 'gpt-4-turbo',
    temperature: 0.1  // Low temp for accuracy
  }
}
```

### Environment Variables
```env
BASE44_AI_API_KEY=your_api_key
BASE44_UPLOAD_DIR=./uploads/evidence
```

## 📊 Sample Investigation Workflow

### Example Case
```
User downloaded PDFEditor.zip from unknown source, 
triggered EDR alert on PDFEditor.exe. It deleted itself. 
Suspect exfil and persistence.
```

### IRHunter Analysis
1. **Artifact Processing**: Extract Registry, Event Logs, Prefetch
2. **Timeline Construction**: Correlate execution timestamps
3. **Pattern Recognition**: Identify PowerShell execution + Registry persistence
4. **MITRE Mapping**: T1566.001 (Phishing), T1059.001 (PowerShell), T1547.001 (Registry Run Keys)
5. **Report Generation**: Comprehensive findings with recommendations

## 🎨 UI/UX Design

### Color Scheme
- **Background**: `#0e1117` (Dark mode)
- **Text**: `#ffffff` (White)
- **Accent**: `#4dd0e1` (Cyan) - Primary actions
- **Success**: `#81c784` (Light green)
- **Error/Alert**: `#e57373` (Soft red)

### Professional Interface
- **Forensic Console**: Not chat-based, investigation-focused
- **Three-Panel Layout**: Upload | Investigation | Case Description
- **Monospace Fonts**: For artifact data and technical details
- **Status Indicators**: Real-time progress and system status

## 🔒 Security Considerations

### Data Handling
- **Local Processing**: Evidence stays on your infrastructure
- **Encrypted Transit**: HTTPS for all communications
- **Temporary Storage**: Automatic cleanup of uploaded files
- **Access Control**: Rate limiting and CORS protection

### Privacy
- **No Data Retention**: Files processed and discarded
- **Local Analysis**: AI processing with data isolation
- **Audit Trail**: Investigation logs for compliance

## 🧪 Testing

### Sample Data
Create test archives with common Windows artifacts:
```
test_evidence.zip
├── Registry/
│   ├── SYSTEM
│   ├── SOFTWARE
│   └── NTUSER.DAT
├── EventLogs/
│   ├── Security.evtx
│   └── System.evtx
├── Prefetch/
│   └── *.pf files
└── Amcache/
    └── Amcache.hve
```

### Test Cases
1. **Malware Execution**: PDF with embedded executable
2. **PowerShell Activity**: Script execution with bypassed policy
3. **Persistence**: Registry Run keys, Scheduled Tasks
4. **Lateral Movement**: Network connections, remote execution

## 📈 Performance

### Optimization
- **Large File Handling**: Streaming upload processing
- **Progressive Analysis**: Real-time progress updates
- **Memory Management**: Efficient artifact parsing
- **Caching**: Artifact metadata for quick correlation

### Scalability
- **Concurrent Processing**: Multiple evidence files
- **Background Jobs**: Non-blocking analysis
- **Resource Monitoring**: Memory and CPU usage tracking

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create feature branch (`git checkout -b feature/awesome-enhancement`)
3. Commit changes (`git commit -am 'Add awesome enhancement'`)
4. Push to branch (`git push origin feature/awesome-enhancement`)
5. Create Pull Request

### Code Standards
- **ESLint**: JavaScript/React linting
- **Prettier**: Code formatting
- **Jest**: Unit testing
- **Documentation**: JSDoc for functions

## 📞 Support

### Documentation
- **Base44 Docs**: https://base44.dev/docs
- **DFIR Resources**: Built-in investigation guides
- **MITRE ATT&CK**: https://attack.mitre.org

### Troubleshooting
- **Upload Issues**: Check file size and format
- **Analysis Errors**: Verify artifact structure
- **PDF Export**: Browser compatibility requirements

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- **Base44 Framework**: AI-first application platform
- **DFIR Community**: Investigation methodologies and best practices
- **MITRE Corporation**: ATT&CK framework integration
- **Open Source**: React, Node.js, and ecosystem libraries

---

**IRHunter v1.0.0** - Professional DFIR investigation at your fingertips 🔍
