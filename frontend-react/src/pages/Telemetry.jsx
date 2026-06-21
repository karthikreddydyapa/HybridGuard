import React, { useState, useEffect } from 'react';
import API from '../api';

export default function Telemetry() {
  const [items, setItems] = useState([]);

  const load = async () => {
    try { const r = await API.get('/dashboard/telemetry?limit=200'); setItems(r.data); }
    catch(e) {}
  };

  useEffect(() => { load(); const t = setInterval(load, 5000); return ()=>clearInterval(t); }, []);

  const TM = {process_created:'#818cf8',network_conn:'#22d3ee',file_created:'#fbbf24',file_renamed:'#fbbf24',heartbeat:'#4ade80'};
  const TL = {process_created:'PROCESS',network_conn:'NETWORK',file_created:'FILE',file_renamed:'RENAMED',heartbeat:'HEARTBEAT'};

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">EDR TELEMETRY FEED ({items.length})</div>
        <div style={{display:'flex',alignItems:'center',gap:'5px',fontFamily:'Share Tech Mono,monospace',fontSize:'9px',color:'#00ff88'}}>
          <div style={{width:'6px',height:'6px',borderRadius:'50%',background:'#00ff88',animation:'blink 2s ease infinite'}}></div>
          LIVE
        </div>
      </div>
      <div style={{maxHeight:'calc(100vh - 200px)',overflowY:'auto'}}>
        {items.length ? items.map((t,i) => (
          <div key={i} style={{display:'flex',alignItems:'center',gap:'10px',padding:'9px 18px',borderBottom:'1px solid #0e2535',fontFamily:'Share Tech Mono,monospace',fontSize:'9px',transition:'background 0.2s'}}
            onMouseEnter={e=>e.currentTarget.style.background='rgba(0,212,255,0.03)'}
            onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
            <div style={{width:'88px',flexShrink:0,padding:'2px 5px',textAlign:'center',fontSize:'8px',letterSpacing:'1px',border:'1px solid',color:TM[t.event_type]||'#818cf8',borderColor:(TM[t.event_type]||'#818cf8')+'66',background:(TM[t.event_type]||'#818cf8')+'11'}}>
              {TL[t.event_type]||t.event_type}
            </div>
            <div style={{flex:1,color:'#5a8fa8'}}>
              {t.process_name&&<b style={{color:'#e0f4ff'}}>{t.process_name}</b>}
              {t.parent_process&&` ← ${t.parent_process}`}
              {t.file_path&&<span style={{color:'#fbbf24'}}>{t.file_path.slice(-50)}</span>}
              {t.dest_ip&&<span> → <span style={{color:'#ff2d55'}}>{t.dest_ip}:{t.dest_port||'?'}</span></span>}
              {!t.process_name&&!t.file_path&&!t.dest_ip&&<span style={{color:'#2a5570'}}>{t.hostname}</span>}
            </div>
            <div style={{color:'#2a5570',flexShrink:0}}>{new Date(t.timestamp).toTimeString().slice(0,8)}</div>
          </div>
        )) : <div className="empty">// NO TELEMETRY DATA</div>}
      </div>
    </div>
  );
}