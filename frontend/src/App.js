import React, { useState } from 'react';
import './App.css';
import LoginPage from './components/LoginPage';

function App() {
  const [token, setToken] = useState(
    localStorage.getItem('ibhp_token')
  );

  const handleLogin = (newToken) => {
    localStorage.setItem('ibhp_token', newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('ibhp_token');
    setToken(null);
  };

  if (!token) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <div className="app">
      <Dashboard onLogout={handleLogout} />
    </div>
  );
}

function Dashboard({ onLogout }) {
  const [activeTab, setActiveTab] = useState('home');

  return (
    <>
      <header className="header">
        <h1>🛡️ IBHP Platform</h1>
        <p>Intelligent Bug Hunting Platform</p>
        <button
          className="logout-btn"
          onClick={onLogout}
        >
          Logout
        </button>
      </header>

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

      <main className="content">
        {activeTab === 'home' && <HomePage />}
        {activeTab === 'device' && <DevicePage />}
        {activeTab === 'app' && <AppPage />}
        {activeTab === 'report' && <ReportPage />}
      </main>
    </>
  );
}

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
        <div className="error-box">❌ {error}</div>
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
                )
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function AppPage() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const startScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const response = await fetch(
        'http://localhost:8000/api/app-scan'
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
      <h2>📦 App Scanner</h2>
      <button
        className="scan-btn"
        onClick={startScan}
        disabled={scanning}
      >
        {scanning ? '⏳ Scanning...' : '🔍 Scan APK'}
      </button>

      {error && (
        <div className="error-box">❌ {error}</div>
      )}

      {results && results.status === 'success' && (
        <div>
          <div className="results-box danger">
            <h3>⚠️ Vulnerabilities:</h3>
            {results.vulnerabilities.length === 0 ? (
              <p>🎉 No Issues Found!</p>
            ) : (
              results.vulnerabilities.map((issue, i) => (
                <div key={i} className="issue-item">
                  <p>🔴 {issue.name}</p>
                  <p>Severity: {issue.severity}</p>
                  <p>Issue: {issue.description}</p>
                  <p>Fix: {issue.remediation}</p>
                </div>
              ))
            )}
          </div>

          <div className="results-box">
            <h3>✅ Secure Items:</h3>
            {results.safe.map((item, i) => (
              <p key={i} className="secure-item">
                ✅ {item.name}: {item.status}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ReportPage() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);

  const generateReport = async () => {
    setLoading(true);
    try {
      const response = await fetch(
        'http://localhost:8000/api/full-scan'
      );
      const data = await response.json();
      setReport(data);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  return (
    <div className="page">
      <h2>📊 Security Reports</h2>
      <button
        className="scan-btn"
        onClick={generateReport}
        disabled={loading}
      >
        {loading ? '⏳ Generating...' : '📊 Generate Report'}
      </button>

      {report && report.status === 'success' && (
        <div className="report-box">
          <h3>🔴 Security Report</h3>
          <div className="report-summary">
            <span className="badge critical">
              Critical: {report.summary.critical}
            </span>
            <span className="badge high">
              High: {report.summary.high}
            </span>
            <span className="badge medium">
              Medium: {report.summary.medium}
            </span>
          </div>

          <div className="results-box danger">
            <h3>⚠️ All Issues:</h3>
            {report.app_vulnerabilities.map(
              (issue, i) => (
                <div key={i} className="issue-item">
                  <p>🔴 {issue.name}</p>
                  <p>Severity: {issue.severity}</p>
                  <p>Fix: {issue.remediation}</p>
                </div>
              )
            )}
          </div>

          {report.ai_analysis && (
            <div className="results-box">
              <h3>🤖 AI Analysis:</h3>
              {report.ai_analysis.map((item, i) => (
                <div key={i} className="issue-item">
                  <p>🔴 {item.vulnerability.name}</p>
                  <pre className="ai-text">
                    {item.ai_analysis}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;