import React, { useState } from 'react';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('home');

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <h1>🛡️ IBHP Platform</h1>
        <p>Intelligent Bug Hunting Platform</p>
      </header>

      {/* Navigation */}
      <nav className="nav">
        <button 
          className={activeTab === 'home' ? 'active' : ''}
          onClick={() => setActiveTab('home')}
        >
          🏠 Home
        </button>
        <button 
          className={activeTab === 'device' ? 'active' : ''}
          onClick={() => setActiveTab('device')}
        >
          📱 Device Scan
        </button>
        <button 
          className={activeTab === 'app' ? 'active' : ''}
          onClick={() => setActiveTab('app')}
        >
          📦 App Scan
        </button>
        <button 
          className={activeTab === 'report' ? 'active' : ''}
          onClick={() => setActiveTab('report')}
        >
          📊 Reports
        </button>
      </nav>

      {/* Content */}
      <main className="content">
        {activeTab === 'home' && <HomePage />}
        {activeTab === 'device' && <DevicePage />}
        {activeTab === 'app' && <AppPage />}
        {activeTab === 'report' && <ReportPage />}
      </main>
    </div>
  );
}

// Home Page
function HomePage() {
  return (
    <div className="page">
      <h2>Welcome to IBHP! 🛡️</h2>
      <div className="cards">
        <div className="card critical">
          <h3>🔴 Critical</h3>
          <p className="number">3</p>
          <p>Issues Found</p>
        </div>
        <div className="card high">
          <h3>🟠 High</h3>
          <p className="number">1</p>
          <p>Issues Found</p>
        </div>
        <div className="card medium">
          <h3>🟡 Medium</h3>
          <p className="number">4</p>
          <p>Issues Found</p>
        </div>
        <div className="card secure">
          <h3>✅ Secure</h3>
          <p className="number">5</p>
          <p>Items Safe</p>
        </div>
      </div>

      <div className="info-box">
        <h3>📱 Device Info</h3>
        <table>
          <tbody>
            <tr>
              <td>Android Version</td>
              <td>15</td>
            </tr>
            <tr>
              <td>Security Patch</td>
              <td>2026-02-05</td>
            </tr>
            <tr>
              <td>SELinux</td>
              <td>Enforcing ✅</td>
            </tr>
            <tr>
              <td>Bootloader</td>
              <td>Locked ✅</td>
            </tr>
            <tr>
              <td>Encryption</td>
              <td>Encrypted ✅</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Device Scan Page
function DevicePage() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const startScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const response = await fetch(
        'http://localhost:8000/api/device-scan'
      );
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError('Server Se Connect Nahi Ho Paya!');
    }
    setScanning(false);
  };

  return (
    <div className="page">
      <h2>📱 Device Scanner</h2>
      <button
        className="scan-btn"
        onClick={startScan}
        disabled={scanning}
      >
        {scanning ? '⏳ Scanning...' : '🔍 Start Scan'}
      </button>

      {error && (
        <div className="error-box">
          ❌ {error}
        </div>
      )}

      {results && results.status === 'success' && (
        <div>
          <div className="results-box">
            <h3>✅ Secure Items:</h3>
            {results.device_safe.map((item, i) => (
              <p key={i} className="secure-item">
                ✅ {item.name}: {item.status}
              </p>
            ))}
          </div>

          <div className="results-box danger">
            <h3>⚠️ Issues Found:</h3>
            {results.device_vulnerabilities.length === 0 ? (
              <p>🎉 No Issues Found!</p>
            ) : (
              results.device_vulnerabilities.map(
                (issue, i) => (
                <div key={i} className="issue-item">
                  <p>🔴 {issue.name}</p>
                  <p>Severity: {issue.severity}</p>
                  <p>Fix: {issue.remediation}</p>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
// App Scan Page
function AppPage() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);

  const startScan = () => {
    setScanning(true);
    setTimeout(() => {
      setResults({
        appInfo: {
          name: 'DIVA App',
          package: 'jakhar.aseem.diva',
          version: '1.0'
        },
        issues: [
          {
            name: 'Debuggable App',
            severity: 'HIGH',
            fix: 'Debug OFF Karo'
          },
          {
            name: 'Backup Allowed',
            severity: 'MEDIUM',
            fix: 'allowBackup=false Karo'
          },
          {
            name: 'Hardcoded Passwords',
            severity: 'CRITICAL',
            fix: 'Secrets Remove Karo'
          }
        ]
      });
      setScanning(false);
    }, 2000);
  };

  return (
    <div className="page">
      <h2>📦 App Scanner</h2>
      <button 
        className="scan-btn"
        onClick={startScan}
        disabled={scanning}
      >
        {scanning ? '⏳ Scanning...' : '🔍 Scan APK'}
      </button>

      {results && (
        <div>
          <div className="info-box">
            <h3>📱 App Info:</h3>
            <p>Name: {results.appInfo.name}</p>
            <p>Package: {results.appInfo.package}</p>
            <p>Version: {results.appInfo.version}</p>
          </div>

          <div className="results-box danger">
            <h3>⚠️ Issues Found:</h3>
            {results.issues.map((issue, i) => (
              <div key={i} className="issue-item">
                <p>🔴 {issue.name}</p>
                <p>Severity: {issue.severity}</p>
                <p>Fix: {issue.fix}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Report Page
function ReportPage() {
  return (
    <div className="page">
      <h2>📊 Security Reports</h2>
      <div className="report-box">
        <h3>🔴 CRITICAL RISK</h3>
        <p>Date: 2026-05-09</p>
        <p>Total Issues: 7</p>
        <div className="report-summary">
          <span className="badge critical">
            Critical: 3
          </span>
          <span className="badge high">
            High: 1
          </span>
          <span className="badge medium">
            Medium: 3
          </span>
        </div>
        <button className="download-btn">
          📥 Download Report
        </button>
      </div>
    </div>
  );
}

export default App;