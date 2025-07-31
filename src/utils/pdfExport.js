import PDFDocument from 'pdfkit';

class PDFExporter {
  constructor() {
    this.doc = null;
    this.pageWidth = 612;
    this.pageHeight = 792;
    this.margin = 50;
    this.contentWidth = this.pageWidth - (this.margin * 2);
  }

  /**
   * Export investigation report to PDF
   */
  async exportReport(report) {
    try {
      this.doc = new PDFDocument({
        size: 'LETTER',
        margins: {
          top: this.margin,
          bottom: this.margin,
          left: this.margin,
          right: this.margin
        }
      });

      // Create blob stream
      const stream = this.doc.pipe();
      const chunks = [];
      
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('end', () => {
        const blob = new Blob(chunks, { type: 'application/pdf' });
        this.downloadPDF(blob, `IRHunter_Report_${report.caseId}.pdf`);
      });

      // Generate PDF content
      this.addHeader(report);
      this.addSummary(report);
      this.addFindings(report);
      this.addIndicators(report);
      this.addRecommendations(report);
      this.addFooter(report);

      // Finalize PDF
      this.doc.end();

    } catch (error) {
      console.error('PDF export failed:', error);
      throw new Error(`PDF export failed: ${error.message}`);
    }
  }

  /**
   * Add report header
   */
  addHeader(report) {
    // Title
    this.doc
      .fontSize(24)
      .fillColor('#4dd0e1')
      .text('🔍 IRHunter Investigation Report', this.margin, this.margin, {
        align: 'center'
      });

    // Case information
    this.doc
      .fontSize(12)
      .fillColor('#000000')
      .moveDown(2)
      .text(`Case ID: ${report.caseId}`, this.margin)
      .text(`Generated: ${new Date(report.timestamp).toLocaleString()}`)
      .text(`Confidence Level: ${report.confidence || 'High'}`)
      .moveDown(1);

    // Add separator line
    this.doc
      .strokeColor('#4dd0e1')
      .lineWidth(2)
      .moveTo(this.margin, this.doc.y)
      .lineTo(this.pageWidth - this.margin, this.doc.y)
      .stroke()
      .moveDown(1);
  }

  /**
   * Add executive summary
   */
  addSummary(report) {
    this.addSectionHeader('Executive Summary');
    
    this.doc
      .fontSize(11)
      .fillColor('#000000')
      .text(report.summary, {
        align: 'justify',
        lineGap: 2
      })
      .moveDown(1.5);
  }

  /**
   * Add investigation findings
   */
  addFindings(report) {
    this.addSectionHeader('Investigation Findings');

    report.findings.forEach((finding, index) => {
      // Check if we need a new page
      if (this.doc.y > this.pageHeight - 150) {
        this.doc.addPage();
      }

      // Finding header
      this.doc
        .fontSize(12)
        .fillColor('#1a1a1a')
        .text(`${index + 1}. ${finding.category}`, {
          underline: true
        });

      // Severity badge
      const severityColor = this.getSeverityColor(finding.severity);
      this.doc
        .fontSize(10)
        .fillColor(severityColor)
        .text(` [${finding.severity.toUpperCase()}]`, {
          continued: true
        })
        .fillColor('#000000');

      // Finding details
      this.doc
        .fontSize(11)
        .moveDown(0.5)
        .text(`Description: ${finding.description}`, {
          lineGap: 2
        })
        .text(`Evidence: ${finding.evidence}`, {
          lineGap: 2
        });

      if (finding.mitre) {
        this.doc.text(`MITRE ATT&CK: ${finding.mitre}`, {
          lineGap: 2
        });
      }

      if (finding.timestamp) {
        this.doc.text(`Timestamp: ${new Date(finding.timestamp).toLocaleString()}`, {
          lineGap: 2
        });
      }

      this.doc.moveDown(1);
    });
  }

  /**
   * Add indicators of compromise
   */
  addIndicators(report) {
    this.addSectionHeader('Indicators of Compromise (IoCs)');

    report.indicators.forEach((ioc, index) => {
      this.doc
        .fontSize(10)
        .fillColor('#000000')
        .text(`${index + 1}. `, {
          continued: true
        })
        .font('Courier')
        .fillColor('#d32f2f')
        .text(ioc)
        .font('Helvetica')
        .fillColor('#000000');
    });

    this.doc.moveDown(1.5);
  }

  /**
   * Add recommendations
   */
  addRecommendations(report) {
    this.addSectionHeader('Recommendations');

    report.recommendations.forEach((rec, index) => {
      this.doc
        .fontSize(11)
        .fillColor('#000000')
        .text(`${index + 1}. ${rec}`, {
          lineGap: 3
        });
    });

    this.doc.moveDown(1.5);
  }

  /**
   * Add section header
   */
  addSectionHeader(title) {
    // Check if we need a new page
    if (this.doc.y > this.pageHeight - 100) {
      this.doc.addPage();
    }

    this.doc
      .fontSize(16)
      .fillColor('#4dd0e1')
      .text(title, {
        underline: true
      })
      .moveDown(1);
  }

  /**
   * Add footer
   */
  addFooter(report) {
    const pages = this.doc.bufferedPageRange();
    
    for (let i = 0; i < pages.count; i++) {
      this.doc.switchToPage(i);
      
      // Add page number
      this.doc
        .fontSize(9)
        .fillColor('#666666')
        .text(
          `Page ${i + 1} of ${pages.count}`,
          this.margin,
          this.pageHeight - 30,
          { align: 'center' }
        );

      // Add generation info
      this.doc
        .text(
          'Generated by IRHunter DFIR Tool',
          this.margin,
          this.pageHeight - 15,
          { align: 'center' }
        );
    }
  }

  /**
   * Get color for severity level
   */
  getSeverityColor(severity) {
    switch (severity?.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  }

  /**
   * Download PDF blob
   */
  downloadPDF(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Clean up
    setTimeout(() => URL.revokeObjectURL(url), 100);
  }

  /**
   * Simple fallback export using HTML2PDF approach
   */
  async exportReportFallback(report) {
    try {
      // Create HTML content
      const htmlContent = this.generateReportHTML(report);
      
      // Create blob and download
      const blob = new Blob([htmlContent], { type: 'text/html' });
      this.downloadPDF(blob, `IRHunter_Report_${report.caseId}.html`);
      
    } catch (error) {
      console.error('Fallback export failed:', error);
      alert('PDF export failed. Please try again or contact support.');
    }
  }

  /**
   * Generate HTML version of report
   */
  generateReportHTML(report) {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>IRHunter Investigation Report - ${report.caseId}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        .header { text-align: center; border-bottom: 2px solid #4dd0e1; padding-bottom: 20px; margin-bottom: 30px; }
        .title { color: #4dd0e1; font-size: 24px; margin-bottom: 10px; }
        .meta { font-size: 12px; color: #666; }
        .section { margin-bottom: 30px; }
        .section-title { color: #4dd0e1; font-size: 18px; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-bottom: 15px; }
        .finding { background: #f5f5f5; padding: 15px; margin-bottom: 15px; border-left: 4px solid #4dd0e1; }
        .severity { padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .severity.critical { background: #ffebee; color: #d32f2f; }
        .severity.high { background: #fff3e0; color: #f57c00; }
        .severity.medium { background: #fffde7; color: #fbc02d; }
        .severity.low { background: #e8f5e8; color: #388e3c; }
        .ioc { font-family: monospace; background: #f5f5f5; padding: 2px 4px; color: #d32f2f; }
        .recommendation { margin-bottom: 10px; }
        @media print { body { margin: 20px; } }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">🔍 IRHunter Investigation Report</div>
        <div class="meta">
            Case ID: ${report.caseId}<br>
            Generated: ${new Date(report.timestamp).toLocaleString()}<br>
            Confidence: ${report.confidence || 'High'}
        </div>
    </div>

    <div class="section">
        <div class="section-title">Executive Summary</div>
        <p>${report.summary}</p>
    </div>

    <div class="section">
        <div class="section-title">Investigation Findings</div>
        ${report.findings.map((finding, index) => `
            <div class="finding">
                <strong>${index + 1}. ${finding.category}</strong>
                <span class="severity ${finding.severity.toLowerCase()}">${finding.severity.toUpperCase()}</span>
                <p><strong>Description:</strong> ${finding.description}</p>
                <p><strong>Evidence:</strong> ${finding.evidence}</p>
                ${finding.mitre ? `<p><strong>MITRE ATT&CK:</strong> ${finding.mitre}</p>` : ''}
                ${finding.timestamp ? `<p><strong>Timestamp:</strong> ${new Date(finding.timestamp).toLocaleString()}</p>` : ''}
            </div>
        `).join('')}
    </div>

    <div class="section">
        <div class="section-title">Indicators of Compromise (IoCs)</div>
        ${report.indicators.map((ioc, index) => `
            <div>${index + 1}. <span class="ioc">${ioc}</span></div>
        `).join('')}
    </div>

    <div class="section">
        <div class="section-title">Recommendations</div>
        ${report.recommendations.map((rec, index) => `
            <div class="recommendation">${index + 1}. ${rec}</div>
        `).join('')}
    </div>

    <div style="margin-top: 50px; text-align: center; font-size: 10px; color: #999;">
        Generated by IRHunter DFIR Tool
    </div>
</body>
</html>`;
  }
}

export default new PDFExporter();