import React from 'react';

export default function MitreMatrix() {
  const covered = new Set(['T1078','T1059','T1136','T1068','T1021','T1071','T1105','T1486','T1110','T1055','T1048','T1190']);
  const tactics = [
    {n:'Initial Access',    t:['T1078','T1190','T1566','T1133','T1195']},
    {n:'Execution',         t:['T1059','T1053','T1569','T1204','T1106']},
    {n:'Persistence',       t:['T1547','T1136','T1543','T1574','T1053']},
    {n:'Privilege Esc',     t:['T1068','T1055','T1548','T1134','T1611']},
    {n:'Lateral Movement',  t:['T1021','T1091','T1210','T1534','T1080']},
    {n:'C2',                t:['T1071','T1095','T1105','T1219','T1572']},
    {n:'Impact',            t:['T1486','T1489','T1498','T1110','T1048']},
  ];

  return (
    <div>
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">MITRE ATT&CK COVERAGE</div>
          <span className="pbadge" style={{color:'#ff2d55'}}>12 TECHNIQUES</span>
        </div>
        <div style={{display:'grid', gridTemplateColumns:'repeat(7,1fr)', gap:'4px', padding:'16px'}}>
          {tactics.map((tac,i) => (
            <div key={i} style={{display:'flex',flexDirection:'column',gap:'3px'}}>
              <div style={{fontFamily:'Share Tech Mono,monospace',fontSize:'7px',letterSpacing:'1px',color:'#00d4ff',textAlign:'center',padding:'6px 4px',background:'rgba(0,212,255,0.08)',border:'1px solid rgba(0,212,255,0.2)',minHeight:'40px',display:'flex',alignItems:'center',justifyContent:'center'}}>
                {tac.n}
              </div>
              {tac.t.map((id,j) => (
                <div key={j} style={{
                  padding:'4px 3px', fontFamily:'Share Tech Mono,monospace', fontSize:'7px',
                  textAlign:'center', border:`1px solid ${covered.has(id)?'rgba(255,45,85,0.6)':'#0e2535'}`,
                  color: covered.has(id)?'#ff2d55':'#2a5570',
                  background: covered.has(id)?'rgba(255,45,85,0.15)':'rgba(255,255,255,0.01)',
                  cursor:'pointer', minHeight:'28px', display:'flex', alignItems:'center', justifyContent:'center',
                  boxShadow: covered.has(id)?'0 0 8px rgba(255,45,85,0.2)':'none',
                  transition:'all 0.2s'
                }} title={id}>
                  {id}{covered.has(id)&&' ●'}
                </div>
              ))}
            </div>
          ))}
        </div>
        <div style={{padding:'14px',display:'flex',gap:'20px',borderTop:'1px solid #0e2535'}}>
          <div style={{display:'flex',alignItems:'center',gap:'6px',fontFamily:'Share Tech Mono,monospace',fontSize:'9px',color:'#5a8fa8'}}>
            <div style={{width:'14px',height:'10px',background:'rgba(255,45,85,0.15)',border:'1px solid rgba(255,45,85,0.6)'}}></div>
            DETECTED BY HYBRIDGUARD
          </div>
          <div style={{display:'flex',alignItems:'center',gap:'6px',fontFamily:'Share Tech Mono,monospace',fontSize:'9px',color:'#5a8fa8'}}>
            <div style={{width:'14px',height:'10px',background:'rgba(255,255,255,0.01)',border:'1px solid #0e2535'}}></div>
            NOT YET COVERED
          </div>
        </div>
      </div>
    </div>
  );
}