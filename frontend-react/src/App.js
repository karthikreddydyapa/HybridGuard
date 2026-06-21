import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import Telemetry from './pages/Telemetry';
import MitreMatrix from './pages/MitreMatrix';
import Agents from './pages/Agents';
import Login from './pages/Login';
import './App.css';

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('hg_token'));
  const [user, setUser]   = useState(JSON.parse(localStorage.getItem('hg_user') || 'null'));

  const logout = () => {
    localStorage.removeItem('hg_token');
    localStorage.removeItem('hg_user');
    setToken(null); setUser(null);
  };

  if (!token) return <Login onLogin={(t, u) => { setToken(t); setUser(u); }} />;

  return (
    <BrowserRouter>
      <div className="app">
        <header className="header">
          <div className="logo">
            <div className="logo-hex">◈</div>
            <div>
              <div className="logo-text">HYBRIDGUARD</div>
              <div className="logo-sub">SECURITY OPERATIONS CENTER</div>
            </div>
          </div>
          <div className="header-mid">
            <div className="threat-pill">
              <div className="blink-dot"></div>
              THREAT LEVEL: HIGH
            </div>
          </div>
          <div className="header-right">
            <span className="user-badge">◈ {user?.username} [{user?.role}]</span>
            <button className="logout-btn" onClick={logout}>LOGOUT</button>
            <div className="clock" id="clock"></div>
          </div>
        </header>

        <div className="body">
          <nav className="sidebar">
            <div className="nav-section">
              <div className="nav-label">// OPERATIONS</div>
              <NavLink to="/" className={({isActive})=>isActive?'ni active':'ni'}>
                <span>◈</span> OVERVIEW
              </NavLink>
              <NavLink to="/alerts" className={({isActive})=>isActive?'ni active':'ni'}>
                <span>⚠</span> ALERTS
              </NavLink>
              <NavLink to="/incidents" className={({isActive})=>isActive?'ni active':'ni'}>
                <span>🔗</span> INCIDENTS
              </NavLink>
            </div>
            <div className="nav-section">
              <div className="nav-label">// DETECTION</div>
              <NavLink to="/telemetry" className={({isActive})=>isActive?'ni active':'ni'}>
                <span>◉</span> EDR FEED
              </NavLink>
              <NavLink to="/mitre" className={({isActive})=>isActive?'ni active':'ni'}>
                <span>⬡</span> MITRE MATRIX
              </NavLink>
              <NavLink to="/agents" className={({isActive})=>isActive?'ni active':'ni'}>
                <span>⬛</span> AGENTS
              </NavLink>
            </div>
          </nav>

          <main className="main">
            <Routes>
              <Route path="/"          element={<Overview token={token}/>}/>
              <Route path="/alerts"    element={<Alerts token={token}/>}/>
              <Route path="/incidents" element={<Incidents token={token}/>}/>
              <Route path="/telemetry" element={<Telemetry token={token}/>}/>
              <Route path="/mitre"     element={<MitreMatrix token={token}/>}/>
              <Route path="/agents"    element={<Agents token={token}/>}/>
              <Route path="*"          element={<Navigate to="/"/>}/>
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}