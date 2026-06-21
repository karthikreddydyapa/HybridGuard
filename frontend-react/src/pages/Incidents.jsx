import React, { useState, useEffect } from 'react';
import API from '../api';

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading]     = useState(true);

  const load = async () => {
    try {
      const r = await API.get('/dashboard/incidents');
      setIncidents(r.data); setLoading(false);
    } catch(e) { setLoading(false); }
  };

  const correlate = async () => {
    await API.post('/dashboard/correlate');
    load();
  };

  useEffect(() => { load(); }, []);

  return (
    <div>
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">CORRELATED INCIDENTS ({incidents.length})</div>
          <div style={{display:'flex',gap:'8px'}}>
            <button className="btn danger" onClick={correlate}>⚡ RUN CORRELATION</button>
            <button className="btn" onClick={load}>↻ REFRESH</button>
          </div>
        </div>
        {loading ? <div className="loading"><div className="spinner"></div>LOADING...</div> :
          incidents.length ?
          <div style={{padding:'14px',display:'flex',flexDirection:'column',gap:'10px'}}>
            {incidents.map((inc,i) => (
              <div key={i} style={{border:'1px solid rgba(255,45,85,0.4)',background:'rgba(255,45,85,0.04)',padding:'14px'}}>
                <div style={{display:'flex',justifyContent:'space-between',marginBottom:'8px'}}>
                  <div style={{fontFamily:'Orbitron,monospace',fontSize:'12px',fontWeight:700,color:'#ff2d55',letterSpacing:'2px'}}>🔗 {inc.title}</div>
                  <span className="pbadge" style={{color:'#ff2d55',fontSize:'8px'}}>{inc.severity}</span>
                </div>
                <div style={{fontFamily:'Share Tech Mono,monospace',fontSize:'9px',color:'#5a8fa8',marginBottom:'8px',lineHeight:1.7}}>{inc.description}</div>
                <div style={{display:'flex',alignItems:'center',gap:'6px',flexWrap:'wrap',marginBottom:'8px'}}>
                  {(inc.mitre_chain||'').split('→').map(t=>t.trim()).filter(Boolean).map((t,idx,arr)=>(
                    <React.Fragment key={idx}>
                      <span style={{fontFamily:'Share Tech Mono,monospace',fontSize:'9px',background:'rgba(255,45,85,0.15)',color:'#ff2d55',border:'1px solid rgba(255,45,85,0.3)',padding:'2px 7px'}}>{t}</span>
                      {idx<arr.length-1&&<span style={{color:'#2a5570'}}>→</span>}
                    </React.Fragment>
                  ))}
                </div>
                <div style={{display:'flex',alignItems:'center',gap:'8px',marginBottom:'8px'}}>
                  <span style={{fontFamily:'Share Tech Mono,monospace',fontSize:'8px',color:'#2a5570',letterSpacing:'2px',whiteSpace:'nowrap'}}>CONFIDENCE</span>
                  <div style={{flex:1,height:'4px',background:'rgba(255,255,255,0.04)',borderRadius:'2px',overflow:'hidden'}}>
                    <div style={{height:'100%',width:`${inc.confidence||0}%`,background:'linear-gradient(90deg,#ff6b35,#ff2d55)'}}></div>
                  </div>
                  <span style={{fontFamily:'Orbitron,monospace',fontSize:'10px',color:'#ff2d55',fontWeight:700}}>{Math.round(inc.confidence||0)}%</span>
                </div>
                <div style={{fontFamily:'Share Tech Mono,monospace',fontSize:'8px',color:'#2a5570',display:'flex',gap:'16px',flexWrap:'wrap'}}>
                  <span>HOST: {inc.hostname||'—'}</span>
                  <span>TACTICS: {inc.tactic_chain||'—'}</span>
                  <span style={{color:inc.status==='OPEN'?'#ff2d55':'#2a5570'}}>● {inc.status}</span>
                </div>
              </div>
            ))}
          </div> :
          <div className="empty">// NO INCIDENTS YET<br/>RUN SIMULATE_ATTACK.PY THEN HIT CORRELATION</div>
        }
      </div>
    </div>
  );
}