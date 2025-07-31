import React, { useState, useRef } from 'react';
import './UploadPanel.css';

const UploadPanel = ({ onFilesUploaded, uploadedFiles }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [password, setPassword] = useState('');
  const [showPasswordInput, setShowPasswordInput] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef(null);

  const allowedTypes = ['.zip', '.rar', '.7z', '.tar', '.gz'];
  const maxSize = 15 * 1024 * 1024 * 1024; // 15GB in bytes

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const files = Array.from(e.dataTransfer.files);
    handleFiles(files);
  };

  const handleFileSelect = (e) => {
    const files = Array.from(e.target.files);
    handleFiles(files);
  };

  const handleFiles = async (files) => {
    const validFiles = [];
    const errors = [];

    for (const file of files) {
      // Check file size
      if (file.size > maxSize) {
        errors.push(`${file.name}: File size exceeds 15GB limit`);
        continue;
      }

      // Check file type
      const extension = '.' + file.name.split('.').pop().toLowerCase();
      if (!allowedTypes.includes(extension)) {
        errors.push(`${file.name}: Unsupported file type. Allowed: ${allowedTypes.join(', ')}`);
        continue;
      }

      validFiles.push(file);
    }

    if (errors.length > 0) {
      alert('Upload errors:\n' + errors.join('\n'));
    }

    if (validFiles.length > 0) {
      // Check if any file might be password protected
      const potentiallyEncrypted = validFiles.some(file => 
        file.name.toLowerCase().includes('password') || 
        file.name.toLowerCase().includes('encrypted')
      );
      
      if (potentiallyEncrypted) {
        setShowPasswordInput(true);
      }

      await uploadFiles(validFiles);
    }
  };

  const uploadFiles = async (files) => {
    setIsUploading(true);
    setUploadProgress(0);

    try {
      // Simulate file upload with progress
      for (let i = 0; i <= 100; i += 10) {
        setUploadProgress(i);
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      // Process files
      const processedFiles = files.map(file => ({
        name: file.name,
        size: file.size,
        type: file.type,
        uploadedAt: new Date().toISOString(),
        id: Math.random().toString(36).substr(2, 9)
      }));

      onFilesUploaded(processedFiles);
      
    } catch (error) {
      console.error('Upload failed:', error);
      alert('Upload failed: ' + error.message);
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const removeFile = (fileId) => {
    const updatedFiles = uploadedFiles.filter(file => file.id !== fileId);
    onFilesUploaded(updatedFiles);
  };

  return (
    <div className="upload-panel">
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Evidence Upload</h3>
          <span className="upload-limit">Max: 15GB</span>
        </div>

        <div 
          className={`upload-zone ${isDragging ? 'dragging' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <div className="upload-icon">📁</div>
          <p className="upload-text">
            Drop forensic files here or click to browse
          </p>
          <p className="upload-subtext">
            Supports: {allowedTypes.join(', ')}
          </p>
          
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept={allowedTypes.join(',')}
            onChange={handleFileSelect}
            style={{ display: 'none' }}
          />
        </div>

        {showPasswordInput && (
          <div className="password-section">
            <label className="form-label">
              Archive Password (if protected):
            </label>
            <input
              type="password"
              className="form-input"
              placeholder="Enter password for encrypted archives"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
        )}

        {isUploading && (
          <div className="upload-progress">
            <div className="progress-bar">
              <div 
                className="progress-fill" 
                style={{ width: `${uploadProgress}%` }}
              ></div>
            </div>
            <span className="progress-text">Uploading... {uploadProgress}%</span>
          </div>
        )}

        <div className="uploaded-files">
          <h4>Uploaded Files ({uploadedFiles.length})</h4>
          {uploadedFiles.length === 0 ? (
            <p className="no-files">No files uploaded yet</p>
          ) : (
            <div className="file-list">
              {uploadedFiles.map(file => (
                <div key={file.id} className="file-item">
                  <div className="file-info">
                    <span className="file-name">{file.name}</span>
                    <span className="file-size">{formatFileSize(file.size)}</span>
                  </div>
                  <button 
                    className="btn-remove"
                    onClick={() => removeFile(file.id)}
                    title="Remove file"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UploadPanel;