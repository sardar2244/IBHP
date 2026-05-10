import React, { useState, useEffect } from 'react';
import './App.css';
import LoginPage from './components/LoginPage';

// ==================
// MAIN APP
// ==================
function App() {
  const [token, setToken] = useState(
    localStorage.getItem('ibhp_token')
  );
  const [username, setUsername] = useState(
    localStorage.getItem('ibhp_user') || 'User'
  );
  const [showRegister, setShowRegister] = useState(false);

  const handleLogin = (newToken, user) => {
    localStorage.setItem('ibhp_token', newToken);
    localStorage.setItem('ibhp_user', user);
    setToken(newToken);
    setUsername(user);
  };

  const handleLogout = () => {
    localStorage.removeItem('ibhp_token');
    localStorage.removeItem('ibhp_user');
    setToken(null);
  };

  if (!token) {
    return showRegister ? (
      <RegisterPage
        onLogin={handleLogin}
        onBack={() => setShowRegister(false)}
      />
    ) : (
      <LoginPage
        onLogin={handleLogin}
        onRegister={() => setShowRegister(true)}
      />
    );
  }

  return (
    <div className="app">
      <Dashboard
        onLogout={handleLogout}
        username={username}
      />
    </div>
  );
}

// ==================
// REGISTER PAGE
// ==================
function RegisterPage({ onLogin, onBack }) {
  const [form, setForm] = useState({
    username: '',
    password: '',
    email: ''
  });
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await fetch(
        'http://localhost:8000/auth/register',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(form)
        }
      );
      const data = await response.json();

      if (data.status === 'success') {
        onLogin(data.token, data.username);
      } else {
        setError(data.detail || data.message || 'Registration Failed!');
      }
    } catch (err) {
      setError('Server Error! ' + err.message);
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <form className="login-form" onSubmit={handleRegister}>
        <h2>🛡️ IBHP Platform</h2>
        <p>Create New Account</p>

        <div className="input-group">
          <label>Username</label>
          <input
            type="text"
            placeholder="Choose username"
            value={form.username}
            onChange={e => setForm({
              ...form, username: e.target.value
            })}
            required
          />
        </div>

        <div className="input-group">
          <label>Email</label>
          <input
            type="email"
            placeholder="Your email"
            value={form.email}
            onChange={e => setForm({
              ...form, email: e.target.value
            })}
            required
          />
        </div>

        <div className="input-group">
          <label>Password</label>
          <input
            type="password"
            placeholder="Choose password"
            value={form.password}
            onChange={e => setForm({
              ...form, password: e.target.value
            })}
            required
          />
        </div>

        {error && (
          <div className="error-box">❌ {error}</div>
        )}

        <button
          type="submit"
          className="scan-btn"
          disabled={loading}
          style={{ width: '100%', justifyContent: 'center' }}
        >
          {loading ? '⏳ Registering...' : '📝 Register'}
        </button>

        <p
          style={{
            color: '#a8a8b3',
            textAlign: 'center',
            marginTop: '15px',
            cursor: 'pointer',
            fontSize: '0.9rem'
          }}
          onClick={onBack}
        >
          ← Back to Login
        </p>
      </form>
    </div>
  );
}

// ==================
// DASHBOARD
// ==================
function Dashboard({ onLogout, username }) {
  const [activeTab, setActiveTab] = useState('home');

  const tabs = [
    { id: 'home', label: '🏠 Home' },
    { id: 'device', label: '📱 Device Scan' },
    { id: 'app', label: '📦 App Scan' },
    { id: 'dynamic', label: '🔄 Dynamic' },
    { id: 'exploit', label: '💥 Exploit' },
    { id: 'report', label: '📊 Reports' },
  ];

  return (
    <>
      <header className="header">
        <div className="header-left">
          <h1>🛡️ IBHP Platform</h1>
          <p>Intelligent Bug Hunting Platform v4.0</p>
        </div>
        <div className="header-right">
          <span className="user-badge">👤 {username}</span>
          <button className="logout-btn" onClick={onLogout}>
            Logout
          </button>
        </div>
      </header>

      <nav className="nav">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={activeTab === tab.id ? 'active' : ''}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {activeTab === 'home' && <HomePage />}
        {activeTab === 'device' && <DevicePage />}
        {activeTab === 'app' && <AppPage />}
        {activeTab === 'dynamic' && <DynamicPage />}
        {activeTab === 'exploit' && <ExploitPage />}
        {activeTab === 'report' && <ReportPage />}
      </main>
    </>
  );
}

// ==================
// HOME PAGE
// ==================
function HomePage() {
  const [deviceStatus, setDeviceStatus] = useState(null);
  const [stats, setStats] = useState({
    critical: 0, high: 0, medium: 0, secure: 0
  });
  const [loading, setLoading] = useState(true);

  const checkDevice = async () => {
    setLoading(true);
    try {
      const response = await fetch(
        'http://localhost:8000/api/check-device'
      );
      const data = await response.json();
      setDeviceStatus(data);

      if (data.connected) {
        const scanRes = await fetch(
          'http://localhost:8000/api/device-scan'
        );
        const scanData = await scanRes.json();
        if (scanData.status === 'success') {
          setStats({
            critical: scanData.summary.critical || 0,
            high: scanData.summary.high || 0,
            medium: scanData.summary.medium || 0,
            secure: scanData.device_safe?.length || 0
          });
        }
      }
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  useEffect(() => {
    checkDevice();
  }, []);

  return (
    <div>
      <h2 className="page-title">🏠 Security Overview</h2>

      {/* Device Status Banner */}
      {deviceStatus && !deviceStatus.connected && (
        <div style={{
          background: 'rgba(231,76,60,0.2)',
          border: '1px solid #e74c3c',
          borderRadius: '10px',
          padding: '20px',
          marginBottom: '20px'
        }}>
          <h3 style={{ color: '#e74c3c' }}>
            ⚠️ No Device Connected!
          </h3>
          <p style={{ color: '#a8a8b3', margin: '10px 0' }}>
            Android Phone Connect Karo:
          </p>
          <ol style={{ color: '#a8a8b3', paddingLeft: '20px' }}>
            <li>USB Cable Se Phone Lagao</li>
            <li>Phone Mein Settings → Developer Options</li>
            <li>USB Debugging ON Karo</li>
            <li>Phone Mein Popup Par "Allow" Click Karo</li>
          </ol>
          <button
            className="scan-btn"
            onClick={checkDevice}
            style={{ marginTop: '15px' }}
          >
            🔄 Check Again
          </button>
        </div>
      )}

      {deviceStatus && deviceStatus.connected && (
        <div style={{
          background: 'rgba(46,204,113,0.2)',
          border: '1px solid #27ae60',
          borderRadius: '10px',
          padding: '15px',
          marginBottom: '20px'
        }}>
          <h3 style={{ color: '#27ae60' }}>
            ✅ Device Connected!
          </h3>
          <p style={{ color: '#a8a8b3' }}>
            Android{' '}
            {deviceStatus.device_info?.android_version}
            {' '}| Patch:{' '}
            {deviceStatus.device_info?.security_patch}
          </p>
        </div>
      )}

      {loading ? (
        <div className="loading">
          <div className="loading-spinner">⚙️</div>
          <p>Checking Device...</p>
        </div>
      ) : (
        <>
          <div className="stats-grid">
            <div className="stat-card critical">
              <div className="icon">🔴</div>
              <div className="number">{stats.critical}</div>
              <div className="label">Critical Issues</div>
            </div>
            <div className="stat-card high">
              <div className="icon">🟠</div>
              <div className="number">{stats.high}</div>
              <div className="label">High Issues</div>
            </div>
            <div className="stat-card medium">
              <div className="icon">🟡</div>
              <div className="number">{stats.medium}</div>
              <div className="label">Medium Issues</div>
            </div>
            <div className="stat-card secure">
              <div className="icon">✅</div>
              <div className="number">{stats.secure}</div>
              <div className="label">Secure Items</div>
            </div>
          </div>

          <div className="info-grid">
            <div className="info-box">
              <h3>📱 Device Info</h3>
              <table className="info-table">
                <tbody>
                  <tr>
                    <td>Connection</td>
                    <td>
                      {deviceStatus?.connected
                        ? '✅ Connected'
                        : '❌ Disconnected'
                      }
                    </td>
                  </tr>
                  <tr>
                    <td>Android Version</td>
                    <td>
                      {deviceStatus?.device_info
                        ?.android_version || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td>Security Patch</td>
                    <td>
                      {deviceStatus?.device_info
                        ?.security_patch || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td>SELinux</td>
                    <td>
                      {deviceStatus?.device_info
                        ?.selinux || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td>Bootloader</td>
                    <td>
                      {deviceStatus?.device_info
                        ?.bootloader || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td>Encryption</td>
                    <td>
                      {deviceStatus?.device_info
                        ?.encryption || 'N/A'}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="info-box">
              <h3>🛡️ Platform Status</h3>
              <table className="info-table">
                <tbody>
                  <tr>
                    <td>Device Scanner</td>
                    <td>✅ Active</td>
                  </tr>
                  <tr>
                    <td>APK Analyzer</td>
                    <td>✅ Active</td>
                  </tr>
                  <tr>
                    <td>Dynamic Analysis</td>
                    <td>✅ Active</td>
                  </tr>
                  <tr>
                    <td>Traffic Analysis</td>
                    <td>✅ No Proxy</td>
                  </tr>
                  <tr>
                    <td>RAG AI Engine</td>
                    <td>✅ Active</td>
                  </tr>
                  <tr>
                    <td>Exploit Engine</td>
                    <td>✅ Active</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ==================
// DEVICE PAGE
// ==================
function DevicePage() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [deviceConnected, setDeviceConnected] = useState(null);

  const checkDevice = async () => {
    try {
      const res = await fetch(
        'http://localhost:8000/api/check-device'
      );
      const data = await res.json();
      setDeviceConnected(data.connected);
      return data.connected;
    } catch {
      setDeviceConnected(false);
      return false;
    }
  };

  const startScan = async () => {
    const connected = await checkDevice();
    if (!connected) {
      setError(
        'Phone Connect Nahi Hai! USB Cable Lagao!'
      );
      return;
    }
    setScanning(true);
    setError(null);
    setResults(null);
    try {
      const response = await fetch(
        'http://localhost:8000/api/device-scan'
      );
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError('Server Error: ' + err.message);
    }
    setScanning(false);
  };

  useEffect(() => {
    checkDevice();
  }, []);

  return (
    <div>
      <h2 className="page-title">📱 Device Scanner</h2>

      {/* Instructions */}
      <div className="info-box" style={{ marginBottom: '20px' }}>
        <h3>📋 How To Use</h3>
        <ol style={{
          color: '#a8a8b3',
          paddingLeft: '20px',
          lineHeight: '2'
        }}>
          <li>Android Phone USB Se Connect Karo</li>
          <li>USB Debugging ON Karo</li>
          <li>Phone Par Allow Click Karo</li>
          <li>"Start Device Scan" Button Click Karo</li>
        </ol>
      </div>

      {/* Device Status */}
      <div style={{
        padding: '10px 15px',
        borderRadius: '8px',
        marginBottom: '15px',
        background: deviceConnected
          ? 'rgba(46,204,113,0.2)'
          : 'rgba(231,76,60,0.2)',
        border: `1px solid ${deviceConnected ? '#27ae60' : '#e74c3c'}`
      }}>
        {deviceConnected === null
          ? '⏳ Checking device...'
          : deviceConnected
            ? '✅ Device Connected - Ready to Scan!'
            : '❌ Device Not Connected - Please Connect Phone'
        }
      </div>

      <button
        className="scan-btn"
        onClick={startScan}
        disabled={scanning}
      >
        {scanning ? '⏳ Scanning...' : '🔍 Start Device Scan'}
      </button>

      {error && (
        <div className="error-box">❌ {error}</div>
      )}

      {scanning && (
        <div className="loading">
          <div className="loading-spinner">⚙️</div>
          <p>Scanning Device Security...</p>
        </div>
      )}

      {results && results.status === 'success' && (
        <>
          <div className="stats-grid"
            style={{ margin: '20px 0' }}
          >
            <div className="stat-card critical">
              <div className="number">
                {results.summary.critical}
              </div>
              <div className="label">Critical</div>
            </div>
            <div className="stat-card high">
              <div className="number">
                {results.summary.high}
              </div>
              <div className="label">High</div>
            </div>
            <div className="stat-card medium">
              <div className="number">
                {results.summary.medium}
              </div>
              <div className="label">Medium</div>
            </div>
            <div className="stat-card secure">
              <div className="number">
                {results.device_safe?.length || 0}
              </div>
              <div className="label">Secure</div>
            </div>
          </div>

          <div className="results-grid">
            <div className="results-box success">
              <h3>✅ Secure Items</h3>
              {results.device_safe?.map((item, i) => (
                <div key={i} className="secure-item">
                  ✅ {item.name}: {item.status}
                </div>
              ))}
            </div>

            <div className="results-box danger">
              <h3>⚠️ Issues Found</h3>
              {results.device_vulnerabilities
                ?.length === 0 ? (
                <div className="secure-item">
                  🎉 No Issues!
                </div>
              ) : (
                results.device_vulnerabilities?.map(
                  (issue, i) => (
                    <div key={i} className="vuln-item">
                      <div className="vuln-header">
                        <span className="vuln-name">
                          {issue.name}
                        </span>
                        <span className={
                          `severity-badge ${issue.severity}`
                        }>
                          {issue.severity}
                        </span>
                      </div>
                      <div className="vuln-fix">
                        🔧 {issue.remediation}
                      </div>
                    </div>
                  )
                )
              )}
            </div>
          </div>

          {results.ai_analysis?.length > 0 && (
            <div className="results-box"
              style={{ marginTop: '20px' }}
            >
              <h3>🤖 AI Analysis (RAG)</h3>
              {results.ai_analysis.map((item, i) => (
                <div key={i} className="ai-box">
                  <strong>{item.vulnerability?.name}</strong>
                  <br />
                  <small style={{ color: '#e94560' }}>
                    CVE: {item.cve} |
                    CVSS: {item.cvss}/10 |
                    {item.owasp}
                  </small>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ==================
// APP SCAN PAGE
// ==================
function AppPage() {
  const [scanning, setScanning] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [uploadedFile, setUploadedFile] = useState(null);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.apk')) {
      setError('Sirf APK File Upload Karo!');
      return;
    }

    setUploading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(
        'http://localhost:8000/api/upload-apk',
        {
          method: 'POST',
          body: formData
        }
      );
      const data = await response.json();
      if (data.status === 'success') {
        setUploadedFile(file.name);
      } else {
        setError(data.message);
      }
    } catch (err) {
      setError('Upload Error: ' + err.message);
    }
    setUploading(false);
  };

  const startScan = async () => {
    setScanning(true);
    setError(null);
    setResults(null);
    try {
      const url = uploadedFile
        ? 'http://localhost:8000/api/scan-uploaded-apk'
        : 'http://localhost:8000/api/app-scan';

      const response = await fetch(url);
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError('Server Error: ' + err.message);
    }
    setScanning(false);
  };

  return (
    <div>
      <h2 className="page-title">📦 APK Scanner</h2>

      {/* Instructions */}
      <div className="info-box"
        style={{ marginBottom: '20px' }}
      >
        <h3>📋 How To Use</h3>
        <ol style={{
          color: '#a8a8b3',
          paddingLeft: '20px',
          lineHeight: '2'
        }}>
          <li>APK File Upload Karo (Ya Default Use Karo)</li>
          <li>"Scan APK" Button Click Karo</li>
          <li>Results Aur AI Analysis Dekho</li>
          <li>Report Download Karo</li>
        </ol>
      </div>

      {/* Upload Section */}
      <div className="info-box"
        style={{ marginBottom: '20px' }}
      >
        <h3>📤 Upload APK</h3>

        <div style={{ marginTop: '15px' }}>
          <input
            type="file"
            accept=".apk"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
            id="apk-upload"
          />
          <label
            htmlFor="apk-upload"
            style={{
              padding: '10px 25px',
              background: '#0f3460',
              color: 'white',
              borderRadius: '8px',
              cursor: 'pointer',
              display: 'inline-block'
            }}
          >
            {uploading
              ? '⏳ Uploading...'
              : '📁 Choose APK File'
            }
          </label>

          {uploadedFile && (
            <span style={{
              marginLeft: '15px',
              color: '#27ae60'
            }}>
              ✅ {uploadedFile}
            </span>
          )}

          {!uploadedFile && (
            <span style={{
              marginLeft: '15px',
              color: '#a8a8b3'
            }}>
              (Default: DIVA APK)
            </span>
          )}
        </div>
      </div>

      <button
        className="scan-btn"
        onClick={startScan}
        disabled={scanning || uploading}
      >
        {scanning ? '⏳ Scanning...' : '🔍 Scan APK'}
      </button>

      {error && (
        <div className="error-box">❌ {error}</div>
      )}

      {scanning && (
        <div className="loading">
          <div className="loading-spinner">⚙️</div>
          <p>Analyzing APK...</p>
          <p style={{ color: '#a8a8b3' }}>
            This may take 1-2 minutes...
          </p>
        </div>
      )}

      {results && results.status === 'success' && (
        <>
          <div style={{
            background: 'rgba(46,204,113,0.1)',
            border: '1px solid #27ae60',
            borderRadius: '8px',
            padding: '10px 15px',
            margin: '15px 0',
            color: '#27ae60'
          }}>
            ✅ APK: {results.apk_file || 'Scanned'}
          </div>

          <div className="stats-grid"
            style={{ margin: '15px 0' }}
          >
            <div className="stat-card critical">
              <div className="number">
                {results.summary?.critical || 0}
              </div>
              <div className="label">Critical</div>
            </div>
            <div className="stat-card high">
              <div className="number">
                {results.summary?.high || 0}
              </div>
              <div className="label">High</div>
            </div>
            <div className="stat-card medium">
              <div className="number">
                {results.summary?.medium || 0}
              </div>
              <div className="label">Medium</div>
            </div>
            <div className="stat-card secure">
              <div className="number">
                {results.safe?.length || 0}
              </div>
              <div className="label">Secure</div>
            </div>
          </div>

          <div className="results-grid">
            <div className="results-box danger">
              <h3>⚠️ Vulnerabilities</h3>
              {results.vulnerabilities?.map(
                (issue, i) => (
                  <div key={i} className="vuln-item">
                    <div className="vuln-header">
                      <span className="vuln-name">
                        {issue.name}
                      </span>
                      <span className={
                        `severity-badge ${issue.severity}`
                      }>
                        {issue.severity}
                      </span>
                    </div>
                    <div className="vuln-fix">
                      {issue.description}
                    </div>
                    <div className="vuln-fix">
                      🔧 {issue.remediation}
                    </div>
                  </div>
                )
              )}
            </div>

            <div className="results-box success">
              <h3>✅ Secure Items</h3>
              {results.safe?.map((item, i) => (
                <div key={i} className="secure-item">
                  ✅ {item.name}: {item.status}
                </div>
              ))}
            </div>
          </div>

          {results.ai_analysis?.length > 0 && (
            <div className="results-box"
              style={{ marginTop: '20px' }}
            >
              <h3>🤖 AI Analysis (RAG + CVE)</h3>
              {results.ai_analysis.map((item, i) => (
                <div key={i} className="ai-box">
                  <strong>
                    {item.vulnerability?.name}
                  </strong>
                  <br />
                  <small style={{ color: '#e94560' }}>
                    CVE: {item.cve} |
                    CVSS: {item.cvss}/10
                  </small>
                  <br />
                  <small style={{ color: '#a8a8b3' }}>
                    {item.owasp}
                  </small>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ==================
// DYNAMIC PAGE
// ==================
function DynamicPage() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [deviceConnected, setDeviceConnected] = useState(null);

  const checkDevice = async () => {
    try {
      const res = await fetch(
        'http://localhost:8000/api/check-device'
      );
      const data = await res.json();
      setDeviceConnected(data.connected);
      return data.connected;
    } catch {
      return false;
    }
  };

  const startScan = async () => {
    const connected = await checkDevice();
    if (!connected) {
      setError('Phone Connect Nahi Hai!');
      return;
    }
    setScanning(true);
    setError(null);
    setResults(null);
    try {
      const response = await fetch(
        'http://localhost:8000/api/dynamic-scan'
      );
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError('Server Error: ' + err.message);
    }
    setScanning(false);
  };

  useEffect(() => { checkDevice(); }, []);

  return (
    <div>
      <h2 className="page-title">🔄 Dynamic Analysis</h2>

      <div className="info-box"
        style={{ marginBottom: '20px' }}
      >
        <h3>📋 How To Use</h3>
        <ol style={{
          color: '#a8a8b3',
          paddingLeft: '20px',
          lineHeight: '2'
        }}>
          <li>Android Phone USB Se Connect Karo</li>
          <li>Phone Par Koi App Open Karo</li>
          <li>"Start Dynamic Scan" Button Click Karo</li>
          <li>Runtime Analysis Results Dekho</li>
        </ol>
        <p style={{
          color: '#e94560',
          marginTop: '10px',
          fontSize: '0.85rem'
        }}>
          ⚡ Method: ADB Logcat + Netstats (No Proxy!)
        </p>
      </div>

      <div style={{
        padding: '10px 15px',
        borderRadius: '8px',
        marginBottom: '15px',
        background: deviceConnected
          ? 'rgba(46,204,113,0.2)'
          : 'rgba(231,76,60,0.2)',
        border: `1px solid ${
          deviceConnected ? '#27ae60' : '#e74c3c'
        }`
      }}>
        {deviceConnected
          ? '✅ Device Connected!'
          : '❌ Device Not Connected!'
        }
      </div>

      <button
        className="scan-btn"
        onClick={startScan}
        disabled={scanning}
      >
        {scanning
          ? '⏳ Analyzing...'
          : '🔄 Start Dynamic Scan'
        }
      </button>

      {error && (
        <div className="error-box">❌ {error}</div>
      )}

      {scanning && (
        <div className="loading">
          <div className="loading-spinner">⚙️</div>
          <p>Running Dynamic Analysis...</p>
          <p style={{ color: '#a8a8b3' }}>
            Analyzing: Logcat + Permissions + Network...
          </p>
        </div>
      )}

      {results && results.status === 'success' && (
        <>
          <div className="info-box"
            style={{ margin: '15px 0' }}
          >
            <h3>📱 Target App</h3>
            <table className="info-table">
              <tbody>
                <tr>
                  <td>Package</td>
                  <td style={{ color: '#e94560' }}>
                    {results.target_package}
                  </td>
                </tr>
                <tr>
                  <td>Total Apps</td>
                  <td>{results.total_apps}</td>
                </tr>
                <tr>
                  <td>Issues Found</td>
                  <td>{results.summary?.total_issues}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="results-grid">
            <div className="results-box danger">
              <h3>⚠️ Runtime Issues</h3>
              {results.dynamic_results
                ?.vulnerabilities?.length === 0 ? (
                <div className="secure-item">
                  🎉 No Issues Found!
                </div>
              ) : (
                results.dynamic_results
                  ?.vulnerabilities?.map(
                  (issue, i) => (
                    <div key={i} className="vuln-item">
                      <div className="vuln-header">
                        <span className="vuln-name">
                          {issue.name}
                        </span>
                        <span className={
                          `severity-badge ${issue.severity}`
                        }>
                          {issue.severity}
                        </span>
                      </div>
                      <div className="vuln-fix">
                        🔧 {issue.remediation}
                      </div>
                    </div>
                  )
                )
              )}
            </div>

            <div className="results-box success">
              <h3>✅ Safe Items</h3>
              {results.dynamic_results?.safe?.map(
                (item, i) => (
                  <div key={i} className="secure-item">
                    ✅ {item.name}: {item.status}
                  </div>
                )
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ==================
// EXPLOIT PAGE
// ==================
function ExploitPage() {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [pkg, setPkg] = useState('com.snapchat.android');
  const [deviceConnected, setDeviceConnected] = useState(null);

  const checkDevice = async () => {
    try {
      const res = await fetch(
        'http://localhost:8000/api/check-device'
      );
      const data = await res.json();
      setDeviceConnected(data.connected);
      return data.connected;
    } catch {
      return false;
    }
  };

  const runExploit = async () => {
    const connected = await checkDevice();
    if (!connected) {
      setError('Phone Connect Nahi Hai!');
      return;
    }
    setRunning(true);
    setError(null);
    setResults(null);
    try {
      const response = await fetch(
        `http://localhost:8000/api/exploit-scan/${pkg}`
      );
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError('Server Error: ' + err.message);
    }
    setRunning(false);
  };

  useEffect(() => { checkDevice(); }, []);

  return (
    <div>
      <h2 className="page-title">💥 Exploit Engine</h2>

      <div className="info-box"
        style={{ marginBottom: '20px' }}
      >
        <h3>🎯 Target Package</h3>
        <input
          type="text"
          value={pkg}
          onChange={e => setPkg(e.target.value)}
          style={{
            width: '100%',
            padding: '10px',
            background: '#1a1a2e',
            border: '1px solid #0f3460',
            color: 'white',
            borderRadius: '6px',
            marginTop: '10px',
            fontFamily: 'monospace'
          }}
          placeholder="com.example.app"
        />
        <p style={{
          color: '#a8a8b3',
          fontSize: '0.8rem',
          marginTop: '8px'
        }}>
          Common packages: com.snapchat.android,
          com.instagram.android, com.facebook.orca
        </p>
      </div>

      <div style={{
        padding: '10px 15px',
        borderRadius: '8px',
        marginBottom: '15px',
        background: deviceConnected
          ? 'rgba(46,204,113,0.2)'
          : 'rgba(231,76,60,0.2)',
        border: `1px solid ${
          deviceConnected ? '#27ae60' : '#e74c3c'
        }`
      }}>
        {deviceConnected
          ? '✅ Device Ready for Testing!'
          : '❌ Device Not Connected!'
        }
      </div>

      <button
        className="scan-btn"
        onClick={runExploit}
        disabled={running}
        style={{ background: running ? '#555' : '#e74c3c' }}
      >
        {running ? '⏳ Running...' : '💥 Run Exploit Tests'}
      </button>

      {error && (
        <div className="error-box">❌ {error}</div>
      )}

      {running && (
        <div className="loading">
          <div className="loading-spinner">💥</div>
          <p>Running Exploit Tests...</p>
        </div>
      )}

      {results && results.status === 'success' && (
        <>
          <div className="info-box"
            style={{ margin: '15px 0' }}
          >
            <h3>📊 Exploit Summary</h3>
            <table className="info-table">
              <tbody>
                <tr>
                  <td>Total Tests</td>
                  <td>{results.summary?.total_tests}</td>
                </tr>
                <tr>
                  <td>Successful Exploits</td>
                  <td style={{ color: '#e74c3c' }}>
                    {results.summary?.successful}
                  </td>
                </tr>
                <tr>
                  <td>Protected</td>
                  <td style={{ color: '#27ae60' }}>
                    {results.summary?.failed}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="results-box danger">
            <h3>💥 Exploit Results</h3>
            {results.exploit_results?.map(
              (result, i) => (
                <div key={i} className="vuln-item">
                  <div className="vuln-header">
                    <span className="vuln-name">
                      {result.name}
                    </span>
                    <span className={`severity-badge ${
                      result.status === 'VULNERABLE'
                        ? 'CRITICAL'
                        : 'LOW'
                    }`}>
                      {result.status}
                    </span>
                  </div>
                  <div className="vuln-fix">
                    {result.description}
                  </div>
                  <div className="vuln-fix">
                    🔧 {result.remediation}
                  </div>
                </div>
              )
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ==================
// REPORT PAGE
// ==================
function ReportPage() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  const generateReport = async () => {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const response = await fetch(
        'http://localhost:8000/api/full-scan'
      );
      const data = await response.json();
      setReport(data);
    } catch (err) {
      setError('Server Error: ' + err.message);
    }
    setLoading(false);
  };

  const downloadReport = () => {
    if (!report) return;
    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: 'application/json' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ibhp_report_${
      new Date().toISOString().split('T')[0]
    }.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h2 className="page-title">📊 Security Reports</h2>

      <div className="info-box"
        style={{ marginBottom: '20px' }}
      >
        <h3>📋 Report Includes</h3>
        <ul style={{
          color: '#a8a8b3',
          paddingLeft: '20px',
          lineHeight: '2'
        }}>
          <li>Device Security Analysis</li>
          <li>APK Static Analysis</li>
          <li>Network Security Check</li>
          <li>AI Analysis with CVE/OWASP Mapping</li>
          <li>Executive Summary</li>
          <li>Remediation Recommendations</li>
        </ul>
      </div>

      <button
        className="scan-btn"
        onClick={generateReport}
        disabled={loading}
      >
        {loading
          ? '⏳ Generating...'
          : '📊 Generate Full Report'
        }
      </button>

      {error && (
        <div className="error-box">❌ {error}</div>
      )}

      {loading && (
        <div className="loading">
          <div className="loading-spinner">📊</div>
          <p>Running All Scans...</p>
          <p style={{ color: '#a8a8b3' }}>
            Device + APK + Network + AI Analysis...
          </p>
        </div>
      )}

      {report && report.status === 'success' && (
        <>
          <div className="report-card">
            <h3>🛡️ IBHP Security Assessment Report</h3>
            <p className="report-meta">
              📅 {new Date(
                report.timestamp
              ).toLocaleString()}
            </p>

            <div className="badge-row">
              <span className="badge critical">
                🔴 Critical: {report.summary?.critical}
              </span>
              <span className="badge high">
                🟠 High: {report.summary?.high}
              </span>
              <span className="badge medium">
                🟡 Medium: {report.summary?.medium}
              </span>
            </div>

            {report.executive_summary && (
              <div className="ai-box"
                style={{ marginTop: '15px' }}
              >
                <pre style={{ fontSize: '0.85rem' }}>
                  {report.executive_summary}
                </pre>
              </div>
            )}

            <button
              className="download-btn"
              onClick={downloadReport}
            >
              📥 Download JSON Report
            </button>
          </div>

          <div className="results-grid">
            <div className="results-box danger">
              <h3>⚠️ All Vulnerabilities</h3>
              {[
                ...(report.device_vulnerabilities || []),
                ...(report.network_vulnerabilities || []),
                ...(report.app_vulnerabilities || [])
              ].map((issue, i) => (
                <div key={i} className="vuln-item">
                  <div className="vuln-header">
                    <span className="vuln-name">
                      {issue.name}
                    </span>
                    <span className={
                      `severity-badge ${issue.severity}`
                    }>
                      {issue.severity}
                    </span>
                  </div>
                  <div className="vuln-fix">
                    🔧 {issue.remediation}
                  </div>
                </div>
              ))}
            </div>

            <div className="results-box">
              <h3>🤖 AI Analysis</h3>
              {report.ai_analysis?.slice(0, 5).map(
                (item, i) => (
                  <div key={i} className="ai-box">
                    <strong>
                      {item.vulnerability?.name}
                    </strong>
                    <br />
                    <small style={{ color: '#e94560' }}>
                      CVE: {item.cve} |
                      CVSS: {item.cvss}/10
                    </small>
                    <br />
                    <small style={{ color: '#a8a8b3' }}>
                      {item.owasp}
                    </small>
                  </div>
                )
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default App;