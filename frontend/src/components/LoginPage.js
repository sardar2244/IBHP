import React, { useState } from 'react';

function LoginPage({ onLogin, onRegister }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const response = await fetch(
        'http://localhost:8000/auth/login',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
        }
      );
      const data = await response.json();
      if (data.status === 'success') {
        onLogin(data.token, data.username);
      } else {
        setError(
          data.detail || data.message || 'Login Failed!'
        );
      }
    } catch (err) {
      setError('Server Error: ' + err.message);
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <form className="login-form" onSubmit={handleLogin}>
        <h2>🛡️ IBHP Platform</h2>
        <p>Intelligent Bug Hunting Platform v4.0</p>

        <div className="input-group">
          <label>Username</label>
          <input
            type="text"
            placeholder="Enter username"
            value={username}
            onChange={e => setUsername(e.target.value)}
            required
          />
        </div>

        <div className="input-group">
          <label>Password</label>
          <input
            type="password"
            placeholder="Enter password"
            value={password}
            onChange={e => setPassword(e.target.value)}
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
          style={{
            width: '100%',
            justifyContent: 'center'
          }}
        >
          {loading ? '⏳ Logging in...' : '🔐 Login'}
        </button>

        <p
          style={{
            color: '#a8a8b3',
            textAlign: 'center',
            marginTop: '15px',
            fontSize: '0.9rem',
            cursor: 'pointer'
          }}
          onClick={onRegister}
        >
          Account Nahi Hai?{' '}
          <span style={{ color: '#e94560' }}>
            Register Karo →
          </span>
        </p>
      </form>
    </div>
  );
}

export default LoginPage;