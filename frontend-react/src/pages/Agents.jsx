import React, { useState, useEffect } from 'react';
import API from '../api';

export default function Agents() {
  const [agents, setAgents] = useState([]);

  const load = async () => {
    try { const r = await API.get('/dashboard/agents'); setAgents(r.data); }
    catch(e) {}
  };

  useEffect(() => { load(); const t = setInterval(load, 10000); return ()=>clearInterval(t); }, []);

  const fago = ts => { const d=(Date.now()-new Date(ts+'Z'))/1000; if(d<60) return Math.floor(d)+'s ago'; if(d<3600) return Math.floor(d/60)+'m ago'; return Math.floor(d/3600)+'h ago'; };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">EDR AGENTS ({agents.length})</div>
        <button className="btn" onClick={load}>↻ REFRESH</button>
      </div>
      {agents.length ? agents.map((a,i) => (
        <div key={i} style={{margin:'10px 14px',padding:'14px',border:'1px solid #0e2535',background:'rgba(0,255,136,0.02)',display:'flex',alignItems:'center',gap:'14px',transition:'all 0.2s'}}
          onMouseEnter={e=>{e.currentTarget.style.borderColor='#00ff88';e.currentTarget.style.boxShadow='0 0 15px rgba(0,255,136,0.1)'}}
          onMouseLeave={e=>{e.currentTarget.style.borderColor='#0e2535';e.currentTarget.style.boxShadow='none'}}>
          <div style={{width:'40px',height:'40px',borderRadius:'50%',border:`2px solid ${a.status==='ONLINE'?'#00ff88':'#2a5570'}`,display:'flex',alignItems:'center',justifyContent:'center',boxShadow:a.status==='ONLINE'?'0 0 12px rgba(0,255,136,0.3)':'none',flexShrink:0}}>
            <span style={{color:a.status==='ONLINE'?'#00ff88':'#2a5570'}}>●</span>
          </div>
          <div style={{flex:1}}>
            <div style={{fontFamily:'Orbitron,monospace',fontSize:'11px',fontWeight:700,color:'#e0f4ff',letterSpacing:'2px',marginBottom:'4px'}}>{a.hostname}</div>
            <div style={{fontFamily:'Share Tech Mono,monospace',fontSize:'9px',color:'#5a8fa8',display:'flex',gap:'12px',flexWrap:'wrap'}}>
              <span>OS: {a.os}</span>
              <span>IP: {a.ip_address}</span>
              <span style={{color:a.status==='ONLINE'?'#00ff88':'#ff2d55'}}>● {a.status}</span>
              <span>LAST: {fago(a.last_seen)}</span>
              <span>ID: {a.agent_id?.slice(0,8)}...</span>
            </div>
          </div>
        </div>
      )) : <div className="empty">// NO AGENTS REGISTERED</div>}
    </div>
  );
}