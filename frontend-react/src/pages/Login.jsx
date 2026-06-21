import React, { useState } from 'react';
import axios from 'axios';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      const form = new URLSearchParams();
      form.append('username', username);
      form.append('password', password);
      const res = await axios.post('http://127.0.0.1:8000/auth/login', form);
      localStorage.setItem('hg_token', res.data.access_token);
      localStorage.setItem('hg_user', JSON.stringify({
        username: res.data.username,
        role: res.data.role,
        full_name: res.data.full_name
      }));
      onLogin(res.data.access_token, res.data);
    } catch(e) {
      setError('Invalid username or password');
    }
    setLoading(false);
  };

  return (
    <div style={{
      display:'flex', alignItems:'center', justifyContent:'center',
      height:'100vh', background:'#020608',
      backgroundImage:'linear-gradient(rgba(0,212,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.03) 1px,transparent 1px)',
      backgroundSize:'40px 40px'
    }}>
      <div style={{
        background:'#0a1520', border:'1px solid #0e2535',
        padding:'48px', width:'380px', position:'relative'
      }}>
        <div style={{textAlign:'center', marginBottom:'32px'}}>
          <div style={{
            width:'56px', height:'56px', border:'2px solid #00d4ff',
            display:'flex', alignItems:'center', justifyContent:'center',
            margin:'0 auto 16px', fontSize:'28px', color:'#00d4ff',
            boxShadow:'0 0 30px rgba(0,212,255,0.5)'
          }}>◈</div>
          <div style={{fontFamily:'Orbitron,monospace', fontSize:'20px', fontWeight:900, color:'#00d4ff', letterSpacing:'4px'}}>HYBRIDGUARD</div>
          <div style={{fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#5a8fa8', letterSpacing:'3px', marginTop:'4px'}}>SECURITY OPERATIONS CENTER</div>
        </div>

        {error && (
          <div style={{
            background:'rgba(255,45,85,0.1)', border:'1px solid rgba(255,45,85,0.4)',
            color:'#ff2d55', padding:'10px 14px', marginBottom:'16px',
            fontFamily:'Share Tech Mono,monospace', fontSize:'10px', letterSpacing:'1px'
          }}>⚠ {error}</div>
        )}

        <form onSubmit={handleLogin}>
          <div style={{marginBottom:'16px'}}>
            <div style={{fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#5a8fa8', letterSpacing:'2px', marginBottom:'6px'}}>// USERNAME</div>
            <input
              value={username} onChange={e=>setUsername(e.target.value)}
              style={{
                width:'100%', background:'#071018', border:'1px solid #0e2535',
                color:'#e0f4ff', padding:'10px 14px', fontFamily:'Share Tech Mono,monospace',
                fontSize:'12px', outline:'none', letterSpacing:'1px'
              }}
              onFocus={e=>e.target.style.borderColor='#00d4ff'}
              onBlur={e=>e.target.style.borderColor='#0e2535'}
            />
          </div>
          <div style={{marginBottom:'24px'}}>
            <div style={{fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#5a8fa8', letterSpacing:'2px', marginBottom:'6px'}}>// PASSWORD</div>
            <input
              type="password" value={password} onChange={e=>setPassword(e.target.value)}
              style={{
                width:'100%', background:'#071018', border:'1px solid #0e2535',
                color:'#e0f4ff', padding:'10px 14px', fontFamily:'Share Tech Mono,monospace',
                fontSize:'12px', outline:'none', letterSpacing:'1px'
              }}
              onFocus={e=>e.target.style.borderColor='#00d4ff'}
              onBlur={e=>e.target.style.borderColor='#0e2535'}
            />
          </div>
          <button type="submit" disabled={loading} style={{
            width:'100%', padding:'12px', background:'rgba(0,212,255,0.1)',
            border:'1px solid #00d4ff', color:'#00d4ff',
            fontFamily:'Orbitron,monospace', fontSize:'11px', fontWeight:700,
            letterSpacing:'3px', cursor:'pointer', transition:'all 0.2s'
          }}>
            {loading ? 'AUTHENTICATING...' : 'LOGIN'}
          </button>
        </form>

        <div style={{marginTop:'20px', textAlign:'center', fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#2a5570', letterSpacing:'1px'}}>
          admin / hybridguard123 &nbsp;|&nbsp; analyst / analyst123
        </div>
      </div>
    </div>
  );
}