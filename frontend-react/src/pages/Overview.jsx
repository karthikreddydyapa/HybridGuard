import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import API from '../api';

export default function Overview({ token }) {
  const [summary, setSummary]     = useState(null);
  const [alerts, setAlerts]       = useState([]);
  const [incidents, setIncidents] = useState([]);

  const load = async () => {
    try {
      const [s, a, i] = await Promise.all([
        API.get('/dashboard/summary'),
        API.get('/dashboard/alerts?limit=10'),
        API.get('/dashboard/incidents')
      ]);
      setSummary(s.data); setAlerts(a.data); setIncidents(i.data);
    } catch(e) { console.error(e); }
  };

  useEffect(() => { load(); const t = setInterval(load, 10000); return ()=>clearInterval(t); }, []);

  const COLORS = { CRITICAL:'#ff2d55', HIGH:'#ff6b35', MEDIUM:'#ffd700', LOW:'#00ff88' };
  const sevData = summary ? Object.entries(summary.severity_breakdown||{}).map(([k,v])=>({name:k,value:v,color:COLORS[k]})) : [];

  const ft = ts => { if(!ts) return '—'; const d=(Date.now()-new Date(ts+'Z'))/1000; if(d<60) return Math.floor(d)+'s ago'; if(d<3600) return Math.floor(d/60)+'m ago'; return Math.floor(d/3600)+'h ago'; };
  const sc = s => ({'CRITICAL':'sev-crit','HIGH':'sev-high','MEDIUM':'sev-med','LOW':'sev-low'}[s]||'sev-low');

  return (
    <div>
      {/* STAT CARDS */}
      <div className="stats-grid">
        {[
          {l:'TOTAL EVENTS 24H', v:summary?.total_events_24h??'—', s:'SIEM + EDR COMBINED', c:'c1'},
          {l:'OPEN ALERTS',      v:summary?.open_alerts??'—',      s:'REQUIRE ATTENTION',   c:'c2'},
          {l:'INCIDENTS',        v:summary?.open_incidents??'—',   s:'CORRELATED CHAINS',   c:'c3'},
          {l:'AGENTS ONLINE',    v:summary?.online_agents??'—',    s:'ENDPOINTS ACTIVE',     c:'c4'},
        ].map((s,i) => (
          <div key={i} className={`stat-card ${s.c}`}>
            <div className="stat-lbl">// {s.l}</div>
            <div className="stat-val">{s.v}</div>
            <div className="stat-sub">{s.s}</div>
          </div>
        ))}
      </div>

      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'16px', marginBottom:'16px'}}>
        {/* SEVERITY PIE */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">SEVERITY BREAKDOWN</div>
            <span className="pbadge" style={{color:'#00d4ff'}}>LIVE</span>
          </div>
          <div style={{padding:'16px'}}>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={sevData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={({name,value})=>`${name}: ${value}`}>
                  {sevData.map((e,i)=><Cell key={i} fill={e.color}/>)}
                </Pie>
                <Tooltip contentStyle={{background:'#0a1520',border:'1px solid #0e2535',color:'#e0f4ff',fontFamily:'Share Tech Mono'}}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* TOP TECHNIQUES */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">TOP TECHNIQUES</div>
          </div>
          <div style={{padding:'16px', display:'flex', flexDirection:'column', gap:'8px'}}>
            {(summary?.top_techniques||[]).map((t,i) => {
              const TN = {'T1110':'Brute Force','T1078':'Valid Accounts','T1059':'Cmd Interpreter','T1486':'Ransomware','T1071':'C2 Channel','T1105':'File Drop','T1021':'Lateral Move'};
              const max = Math.max(...(summary?.top_techniques||[]).map(x=>x.count));
              return (
                <div key={i} style={{display:'flex', alignItems:'center', gap:'10px'}}>
                  <div style={{fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#00d4ff', width:'46px'}}>{t.mitre_id}</div>
                  <div style={{flex:1, height:'6px', background:'rgba(255,255,255,0.04)', borderRadius:'3px', overflow:'hidden'}}>
                    <div style={{height:'100%', width:`${(t.count/max)*100}%`, background:'#ff6b35', boxShadow:'0 0 8px #ff6b35', transition:'width 1s ease'}}></div>
                  </div>
                  <div style={{fontFamily:'Orbitron,monospace', fontSize:'11px', fontWeight:700, color:'#ff6b35', width:'24px'}}>{t.count}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ACTIVE INCIDENTS */}
      {incidents.length > 0 && (
        <div className="panel" style={{marginBottom:'16px'}}>
          <div className="panel-header">
            <div className="panel-title">ACTIVE INCIDENTS</div>
            <span className="pbadge" style={{color:'#ff2d55'}}>CORRELATED</span>
          </div>
          <div style={{padding:'14px', display:'flex', flexDirection:'column', gap:'10px'}}>
            {incidents.slice(0,3).map((inc,i) => (
              <div key={i} style={{border:'1px solid rgba(255,45,85,0.4)', background:'rgba(255,45,85,0.04)', padding:'14px', animation:'incGlow 3s ease infinite'}}>
                <div style={{display:'flex', justifyContent:'space-between', marginBottom:'8px'}}>
                  <div style={{fontFamily:'Orbitron,monospace', fontSize:'11px', fontWeight:700, color:'#ff2d55', letterSpacing:'2px'}}>🔗 {inc.title}</div>
                  <span className="pbadge" style={{color:'#ff2d55', fontSize:'8px'}}>{inc.severity}</span>
                </div>
                <div style={{fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#5a8fa8', marginBottom:'8px'}}>{inc.description}</div>
                <div style={{display:'flex', alignItems:'center', gap:'6px', flexWrap:'wrap', marginBottom:'8px'}}>
                  {(inc.mitre_chain||'').split('→').map(t=>t.trim()).filter(Boolean).map((t,idx,arr)=>(
                    <React.Fragment key={idx}>
                      <span style={{fontFamily:'Share Tech Mono,monospace', fontSize:'9px', background:'rgba(255,45,85,0.15)', color:'#ff2d55', border:'1px solid rgba(255,45,85,0.3)', padding:'2px 7px'}}>{t}</span>
                      {idx<arr.length-1 && <span style={{color:'#2a5570'}}>→</span>}
                    </React.Fragment>
                  ))}
                </div>
                <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
                  <span style={{fontFamily:'Share Tech Mono,monospace', fontSize:'8px', color:'#2a5570', letterSpacing:'2px'}}>CONFIDENCE</span>
                  <div style={{flex:1, height:'4px', background:'rgba(255,255,255,0.04)', borderRadius:'2px', overflow:'hidden'}}>
                    <div style={{height:'100%', width:`${inc.confidence||0}%`, background:'linear-gradient(90deg,#ff6b35,#ff2d55)', boxShadow:'0 0 8px #ff2d55'}}></div>
                  </div>
                  <span style={{fontFamily:'Orbitron,monospace', fontSize:'10px', color:'#ff2d55', fontWeight:700}}>{Math.round(inc.confidence||0)}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* LIVE ALERTS */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">LIVE ALERT FEED</div>
          <div style={{display:'flex', alignItems:'center', gap:'10px'}}>
            <div style={{display:'flex', alignItems:'center', gap:'5px', fontFamily:'Share Tech Mono,monospace', fontSize:'9px', color:'#00ff88'}}>
              <div className="blink-dot" style={{width:'6px',height:'6px',background:'#00ff88'}}></div>AUTO-REFRESH
            </div>
            <button className="btn" onClick={load}>↻ REFRESH</button>
          </div>
        </div>
        <div>
          {alerts.length ? alerts.map((a,i) => (
            <div key={i} className="alert-row">
              <div className={`asev ${sc(a.severity)}`} style={{fontFamily:'Share Tech Mono,monospace', fontSize:'8px', letterSpacing:'2px', padding:'3px 6px', textAlign:'center', border:'1px solid currentColor', fontWeight:'bold'}}>{a.severity}</div>
              <div>
                <div className="alert-rule">{a.rule_name}</div>
                <div className="alert-meta">
                  <span className="mtag">{a.mitre_id}</span>
                  <span className={a.source==='SIEM'?'src-siem':'src-edr'}>{a.source}</span>
                  {a.hostname && <span>⬛ {a.hostname}</span>}
                  {a.username && <span>◈ {a.username}</span>}
                </div>
              </div>
              <div className="atime">
                <div>{new Date(a.timestamp).toTimeString().slice(0,8)}</div>
                <div style={{marginTop:'2px'}}>{ft(a.timestamp)}</div>
                <div style={{marginTop:'3px', fontSize:'8px', color: a.status==='OPEN'?'#ff2d55':'#2a5570'}}>{a.status}</div>
              </div>
            </div>
          )) : <div className="empty">// NO ALERTS</div>}
        </div>
      </div>
    </div>
  );
}