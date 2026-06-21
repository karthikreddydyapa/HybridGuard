import React, { useState, useEffect } from 'react';
import API from '../api';

export default function Alerts() {
  const [alerts, setAlerts]   = useState([]);
  const [filter, setFilter]   = useState('ALL');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const r = await API.get('/dashboard/alerts?limit=200');
      setAlerts(r.data); setLoading(false);
    } catch(e) { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const sc = s => ({'CRITICAL':'sev-crit','HIGH':'sev-high','MEDIUM':'sev-med','LOW':'sev-low'}[s]||'sev-low');
  const filtered = filter === 'ALL' ? alerts : alerts.filter(a => a.severity === filter);
  const ft = ts => { const d=(Date.now()-new Date(ts+'Z'))/1000; if(d<60) return Math.floor(d)+'s ago'; if(d<3600) return Math.floor(d/60)+'m ago'; return Math.floor(d/3600)+'h ago'; };

  return (
    <div>
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">ALL ALERTS ({filtered.length})</div>
          <div style={{display:'flex', gap:'8px'}}>
            {['ALL','CRITICAL','HIGH','MEDIUM','LOW'].map(f => (
              <button key={f} className="btn" onClick={()=>setFilter(f)}
                style={{borderColor: filter===f ? '#00d4ff':'', color: filter===f ? '#00d4ff':''}}>
                {f}
              </button>
            ))}
            <button className="btn" onClick={load}>↻</button>
          </div>
        </div>
        {loading ? <div className="loading"><div className="spinner"></div>LOADING...</div> :
          filtered.length ? filtered.map((a,i) => (
            <div key={i} className="alert-row">
              <div className={`asev ${sc(a.severity)}`} style={{fontFamily:'Share Tech Mono,monospace',fontSize:'8px',letterSpacing:'2px',padding:'3px 6px',textAlign:'center',border:'1px solid currentColor',fontWeight:'bold'}}>{a.severity}</div>
              <div>
                <div className="alert-rule">{a.rule_name}</div>
                <div className="alert-meta">
                  <span className="mtag">{a.mitre_id}</span>
                  <span className={a.source==='SIEM'?'src-siem':'src-edr'}>{a.source}</span>
                  {a.hostname&&<span>⬛ {a.hostname}</span>}
                  {a.username&&<span>◈ {a.username}</span>}
                  {a.source_ip&&<span>⬡ {a.source_ip}</span>}
                </div>
                <div style={{fontFamily:'Share Tech Mono,monospace',fontSize:'9px',color:'#2a5570',marginTop:'3px'}}>{a.description?.slice(0,80)}</div>
              </div>
              <div className="atime">
                <div>{new Date(a.timestamp).toTimeString().slice(0,8)}</div>
                <div>{ft(a.timestamp)}</div>
                <div style={{color:a.status==='OPEN'?'#ff2d55':'#2a5570',fontSize:'8px',marginTop:'2px'}}>{a.status}</div>
              </div>
            </div>
          )) : <div className="empty">// NO ALERTS MATCH FILTER</div>
        }
      </div>
    </div>
  );
}