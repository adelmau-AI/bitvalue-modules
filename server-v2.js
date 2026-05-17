'use strict';
const net=require('net');
const http=require('http');
const fs=require('fs');
const EventEmitter=require('events');

const WHITELIST_FILE='/opt/bitvalue/devices.json';
const METRICS_FILE='/opt/bitvalue/metrics.json';

function isAllowed(imei){
  try{const d=JSON.parse(fs.readFileSync(WHITELIST_FILE,'utf8'));return d.whitelist.includes(imei);}
  catch{return false;}
}

function loadMetrics(){
  try{return JSON.parse(fs.readFileSync(METRICS_FILE,'utf8'));}
  catch{return {};}
}

function saveMetrics(m){
  try{fs.writeFileSync(METRICS_FILE,JSON.stringify(m));}
  catch(e){console.error('metrics save error',e);}
}

const store={devices:{},events:new EventEmitter()};
const metrics=loadMetrics();

const CRC_TABLE=[0x0000,0x1189,0x2312,0x329b,0x4624,0x57ad,0x6536,0x74bf,0x8c48,0x9dc1,0xaf5a,0xbed3,0xca6c,0xdbe5,0xe97e,0xf8f7,0x1081,0x0108,0x3393,0x221a,0x56a5,0x472c,0x75b7,0x643e,0x9cc9,0x8d40,0xbfdb,0xae52,0xdaed,0xcb64,0xf9ff,0xe876,0x2102,0x308b,0x0210,0x1399,0x6726,0x76af,0x4434,0x55bd,0xad4a,0xbcc3,0x8e58,0x9fd1,0xeb6e,0xfae7,0xc87c,0xd9f5,0x3183,0x200a,0x1291,0x0318,0x77a7,0x662e,0x54b5,0x453c,0xbdcb,0xac42,0x9ed9,0x8f50,0xfbef,0xea66,0xd8fd,0xc974,0x4204,0x538d,0x6116,0x709f,0x0420,0x15a9,0x2732,0x36bb,0xce4c,0xdfc5,0xed5e,0xfcd7,0x8868,0x99e1,0xab7a,0xbaf3,0x5285,0x430c,0x7197,0x601e,0x14a1,0x0528,0x37b3,0x263a,0xdecd,0xcf44,0xfddf,0xec56,0x98e9,0x8960,0xbbfb,0xaa72,0x6306,0x728f,0x4014,0x519d,0x2522,0x34ab,0x0630,0x17b9,0xef4e,0xfec7,0xcc5c,0xddd5,0xa96a,0xb8e3,0x8a78,0x9bf1,0x7387,0x620e,0x5095,0x411c,0x35a3,0x242a,0x16b1,0x0738,0xffcf,0xee46,0xdcdd,0xcd54,0xb9eb,0xa862,0x9af9,0x8b70,0x8408,0x9581,0xa71a,0xb693,0xc22c,0xd3a5,0xe13e,0xf0b7,0x0840,0x19c9,0x2b52,0x3adb,0x4e64,0x5fed,0x6d76,0x7cff,0x9489,0x8500,0xb79b,0xa612,0xd2ad,0xc324,0xf1bf,0xe036,0x18c1,0x0948,0x3bd3,0x2a5a,0x5ee5,0x4f6c,0x7df7,0x6c7e,0xa50a,0xb483,0x8618,0x9791,0xe32e,0xf2a7,0xc03c,0xd1b5,0x2942,0x38cb,0x0a50,0x1bd9,0x6f66,0x7eef,0x4c74,0x5dfd,0xb58b,0xa402,0x9699,0x8710,0xf3af,0xe226,0xd0bd,0xc134,0x39c3,0x284a,0x1ad1,0x0b58,0x7fe7,0x6e6e,0x5cf5,0x4d7c,0xc60c,0xd785,0xe51e,0xf497,0x8028,0x91a1,0xa33a,0xb2b3,0x4a44,0x5bcd,0x6956,0x78df,0x0c60,0x1de9,0x2f72,0x3efb,0xd68d,0xc704,0xf59f,0xe416,0x90a9,0x8120,0xb3bb,0xa232,0x5ac5,0x4b4c,0x79d7,0x685e,0x1ce1,0x0d68,0x3ff3,0x2e7a,0xe70e,0xf687,0xc41c,0xd595,0xa12a,0xb0a3,0x8238,0x93b1,0x6b46,0x7acf,0x4854,0x59dd,0x2d62,0x3ceb,0x0e70,0x1ff9,0xf78f,0xe606,0xd49d,0xc514,0xb1ab,0xa022,0x92b9,0x8330,0x7bc7,0x6a4e,0x58d5,0x495c,0x3de3,0x2c6a,0x1ef1,0x0f78];

function calcCRC(buf){let fcs=0xffff;for(let i=0;i<buf.length;i++){fcs=(fcs>>8)^CRC_TABLE[(fcs^buf[i])&0xff];}return(~fcs)&0xffff;}
function verifyCRC(p){const c=calcCRC(p.slice(2,p.length-4));const r=(p[p.length-4]<<8)|p[p.length-3];return c===r;}
function buildResponse(proto,serial){const b=Buffer.alloc(10);b[0]=0x78;b[1]=0x78;b[2]=0x05;b[3]=proto;b[4]=(serial>>8)&0xff;b[5]=serial&0xff;const c=calcCRC(b.slice(2,6));b[6]=(c>>8)&0xff;b[7]=c&0xff;b[8]=0x0D;b[9]=0x0A;return b;}
function decodeCoord(r){const m=r/30000;const d=Math.floor(m/60);return d+(m%60)/60;}
function parseIMEI(buf,o){let s='';for(let i=0;i<8;i++)s+=buf[o+i].toString(16).padStart(2,'0');return s.slice(0,15);}

function parseGPS(buf,o){
  const gb=buf[o];const sats=gb&0x0f;
  const lat=decodeCoord(buf.readUInt32BE(o+1));
  const lng=decodeCoord(buf.readUInt32BE(o+5));
  const speed=buf[o+9];
  const cs=buf.readUInt16BE(o+10);
  const sb=(cs>>8)&0xff;
  const north=(sb&0x04)!==0;const east=(sb&0x08)===0;const located=(sb&0x10)!==0;
  return{lat:north?lat:-lat,lng:east?lng:-lng,speed,course:cs&0x03ff,satellites:sats,located};
}

function parseStatus(d,v,g){
  const alarms=['Normal','Vibration','Cut-off','Low Power','SOS'];
  const volts=['Off','Critical','Low Alarm','Low','OK','OK','OK'];
  const gsms=['No signal','Weak','Weak','Good','Strong'];
  return{accHigh:(d&0x02)!==0,charging:(d&0x04)!==0,engineOn:(d&0x80)===0,
    gpsLocated:(d&0x40)!==0,alarm:alarms[(d>>3)&0x07]||'Unknown',
    voltage:volts[Math.min(v,6)],gsm:gsms[Math.min(g,4)]};
}

function haversine(lat1,lng1,lat2,lng2){
  const R=6371000,r=Math.PI/180;
  const dLat=(lat2-lat1)*r,dLng=(lng2-lng1)*r;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*r)*Math.cos(lat2*r)*Math.sin(dLng/2)**2;
  return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}


function initMetrics(imei){
  if(!metrics[imei])metrics[imei]={
    // Odómetro y horómetro
    km_total:0, km_session:0,
    engine_hours:0, engine_hours_session:0,
    // Sesión actual
    session_start:null, session_km:0,
    trip_count_today:0, trips_today:[],
    last_acc_on:null, last_position:null,
    // Velocidad
    speed_max_session:0, speed_sum:0, speed_count:0,
    speed_max_ever:0,
    // Perfil operación
    time_idle:0, time_urban:0, time_highway:0, time_stress:0,
    // Eventos conducción
    hard_braking:0, hard_accel:0, last_speed:0, last_speed_time:null,
    // ISS suspensión
    vibration_count:0, vibration_per_100km:0,
    iss_baseline:null, iss_history:[],
    // Eléctrico
    voltage_history:[], charge_cycles:0, last_charging:false,
    voltage_drops:0,
    // Score
    driving_score:100,
    // Sprocket
    sprocket_vibrations:0, sprocket_index:0,
    // Predicción mantenimiento
    maintenance:{
      oil:{km_at_last:0,interval:3000,status:'ok'},
      brakes:{km_at_last:0,interval:10000,hard_braking_count:0,status:'ok'},
      chain:{km_at_last:0,interval:5000,status:'ok'},
      tires:{km_at_last:0,interval:20000,status:'ok'},
      suspension:{iss_at_last:0,status:'ok'},
      filter:{km_at_last:0,interval:8000,status:'ok'},
      battery:{status:'ok',drops:0},
      wiring:{status:'ok',anomalies:0},
    },
    updated_at:new Date().toISOString(),
  };
  return metrics[imei];
}

function updateMetrics(imei,gps,status,now){
  const m=initMetrics(imei);
  const t=now||Date.now();

  // ACC ON — inicio de sesión
  if(status&&status.accHigh&&!m.last_acc_on){
    m.last_acc_on=t;
    m.session_km=0;
    m.speed_max_session=0;
    m.session_start=new Date(t).toISOString();
  }

  // ACC OFF — fin de sesión
  if(status&&!status.accHigh&&m.last_acc_on){
    const dur=(t-m.last_acc_on)/3600000;
    m.engine_hours+=dur;
    m.trip_count_today++;
    m.trips_today.push({
      start:m.session_start,
      end:new Date(t).toISOString(),
      km:parseFloat(m.session_km.toFixed(2)),
      duration_min:Math.round((t-m.last_acc_on)/60000),
      max_speed:m.speed_max_session,
    });
    if(m.trips_today.length>20)m.trips_today.shift();
    m.last_acc_on=null;
  }

  if(gps&&gps.located&&gps.lat&&gps.lng){
    const spd=gps.speed||0;

    // Distancia Haversine
    if(m.last_position&&m.last_position.lat){
      const dist=haversine(m.last_position.lat,m.last_position.lng,gps.lat,gps.lng);
      const km=dist/1000;
      if(km<2){
        m.km_total+=km;
        m.session_km+=km;
        m.km_session+=km;
      }
    }
    m.last_position={lat:gps.lat,lng:gps.lng,time:t};

    // Velocidad máxima
    if(spd>m.speed_max_session)m.speed_max_session=spd;
    if(spd>m.speed_max_ever)m.speed_max_ever=spd;
    m.speed_sum+=spd;m.speed_count++;

    // Perfil operación
    if(status&&status.accHigh){
      const dt=10;
      if(spd===0)m.time_idle+=dt;
      else if(spd<=60)m.time_urban+=dt;
      else if(spd<=100)m.time_highway+=dt;
      else m.time_stress+=dt;
    }

    // Aceleración/frenada brusca
    if(m.last_speed_time){
      const dt=(t-m.last_speed_time)/1000;
      if(dt>0&&dt<30){
        const dv=spd-m.last_speed;
        if(dv>15){m.hard_accel++;m.driving_score=Math.max(0,m.driving_score-3);}
        if(dv<-15){m.hard_braking++;m.driving_score=Math.max(0,m.driving_score-4);
          m.maintenance.brakes.hard_braking_count++;}
      }
    }
    m.last_speed=spd;m.last_speed_time=t;
  }

  // Voltaje y ramal eléctrico
  if(status){
    const vmap={Off:0,Critical:1,'Low Alarm':2,Low:3,OK:5};
    const vnum=vmap[status.voltage]||0;
    m.voltage_history.push({v:vnum,t:new Date(t).toISOString()});
    if(m.voltage_history.length>100)m.voltage_history.shift();
    if(vnum<=2&&m.last_voltage>3){m.voltage_drops++;m.maintenance.wiring.anomalies++;
      if(m.voltage_drops>3)m.maintenance.wiring.status='warning';}
    if(status.charging&&!m.last_charging)m.charge_cycles++;
    m.last_charging=status.charging;
    m.last_voltage=vnum;
    if(m.charge_cycles>300)m.maintenance.battery.status='warning';
  }

  // Predicción mantenimiento
  const km=m.km_total;
  const checkComp=(comp,interval)=>{
    const remaining=interval-(km-comp.km_at_last);
    if(remaining<interval*0.1)comp.status='critical';
    else if(remaining<interval*0.2)comp.status='warning';
    else comp.status='ok';
    comp.remaining_km=Math.max(0,Math.round(remaining));
  };
  checkComp(m.maintenance.oil,m.maintenance.oil.interval);
  checkComp(m.maintenance.brakes,m.maintenance.brakes.interval);
  checkComp(m.maintenance.chain,m.maintenance.chain.interval);
  checkComp(m.maintenance.tires,m.maintenance.tires.interval);
  checkComp(m.maintenance.filter,m.maintenance.filter.interval);

  // Score conducción — recuperación lenta
  if(m.speed_count%20===0)m.driving_score=Math.min(100,m.driving_score+1);

  // Perfil % operación
  const total_time=m.time_idle+m.time_urban+m.time_highway+m.time_stress||1;
  m.operation_profile={
    idle:Math.round(m.time_idle/total_time*100),
    urban:Math.round(m.time_urban/total_time*100),
    highway:Math.round(m.time_highway/total_time*100),
    stress:Math.round(m.time_stress/total_time*100),
  };

  m.updated_at=new Date(t).toISOString();
  return m;
}

function updateISS(imei,alarmType){
  const m=initMetrics(imei);
  if(alarmType==='Vibration'){
    m.vibration_count++;
    if(m.km_total>0)m.vibration_per_100km=(m.vibration_count/m.km_total)*100;
    // Sprocket — vibración durante aceleración
    if(m.last_speed>20&&m.last_speed<60)m.sprocket_vibrations++;
    m.sprocket_index=m.km_total>0?(m.sprocket_vibrations/m.km_total)*100:0;
    // ISS baseline
    if(!m.iss_baseline&&m.km_total>500)m.iss_baseline=m.vibration_per_100km;
    if(m.iss_baseline){
      const deviation=(m.vibration_per_100km-m.iss_baseline)/m.iss_baseline*100;
      if(deviation>100)m.maintenance.suspension.status='critical';
      else if(deviation>60)m.maintenance.suspension.status='warning';
      else m.maintenance.suspension.status='ok';
      m.iss_deviation=Math.round(deviation);
    }
    m.iss_history.push({iss:parseFloat(m.vibration_per_100km.toFixed(2)),t:new Date().toISOString()});
    if(m.iss_history.length>200)m.iss_history.shift();
  }
}


function updateDevice(imei,data){
  if(!imei||imei==='unknown')return;
  if(!store.devices[imei])store.devices[imei]={imei,history:[],alerts:[]};
  const dev=store.devices[imei];
  Object.assign(dev,data);
  dev.lastSeen=new Date().toISOString();
  if(data.location){
    dev.history.push({...data.location,time:dev.lastSeen});
    if(dev.history.length>500)dev.history.shift();
  }
  // Actualizar métricas
  if(data.location||data.status){
    const m=updateMetrics(imei,data.location,data.status,Date.now());
    dev.metrics=m;
  }
  // ISS
  if(data.status&&data.status.alarm==='Vibration')updateISS(imei,data.status.alarm);
  store.events.emit('update',{imei,...data});
  // Guardar métricas cada 10 paquetes
  if(!store.devices[imei]._pktCount)store.devices[imei]._pktCount=0;
  store.devices[imei]._pktCount++;
  if(store.devices[imei]._pktCount%10===0)saveMetrics(metrics);
}

const server=net.createServer(socket=>{
  socket._buf=Buffer.alloc(0);socket._imei=null;
  socket.on('data',data=>{
    socket._buf=Buffer.concat([socket._buf,data]);
    while(socket._buf.length>=5){
      if(socket._buf[0]!==0x78||socket._buf[1]!==0x78){socket._buf=socket._buf.slice(1);continue;}
      const len=socket._buf[2]+5;
      if(socket._buf.length<len)break;
      const pkt=socket._buf.slice(0,len);
      socket._buf=socket._buf.slice(len);
      if(!verifyCRC(pkt))continue;
      const proto=pkt[3];
      const serial=(pkt[pkt.length-6]<<8)|pkt[pkt.length-5];
      const imei=socket._imei||'unknown';
      switch(proto){
        case 0x01:{
          const id=parseIMEI(pkt,4);
          if(!isAllowed(id)){console.log(`[BLOCKED] IMEI=${id}`);socket.destroy();return;}
          socket._imei=id;
          updateDevice(id,{connected:true});
          console.log(`[LOGIN] IMEI=${id}`);
          socket.write(buildResponse(0x01,serial));
          break;}
        case 0x10:{
          const gps=parseGPS(pkt,4);
          updateDevice(imei,{location:gps});
          console.log(`[GPS] ${imei} lat=${gps.lat.toFixed(5)} lng=${gps.lng.toFixed(5)} spd=${gps.speed}`);
          break;}
        case 0x13:{
          const st=parseStatus(pkt[4],pkt[5],pkt[6]);
          updateDevice(imei,{status:st});
          console.log(`[STATUS] ${imei} ACC=${st.accHigh} alarm=${st.alarm} volt=${st.voltage}`);
          socket.write(buildResponse(0x13,serial));
          break;}
        case 0x12:case 0x16:{
          const gps=parseGPS(pkt,4);
          const so=4+(pkt[4]&0x0f?12:0)+12;
          const st=so+3<=pkt.length-4?parseStatus(pkt[so],pkt[so+1],pkt[so+2]):null;
          if(st)updateDevice(imei,{location:gps,status:st});
          else updateDevice(imei,{location:gps});
          if(proto===0x16)socket.write(buildResponse(proto,serial));
          break;}
        default:break;
      }
      store.events.emit('packet',{proto,imei});
    }
  });
  socket.on('close',()=>{
    if(socket._imei){
      updateDevice(socket._imei,{connected:false});
      saveMetrics(metrics);
    }
  });
  socket.on('error',()=>{});
});

const httpServer=http.createServer((req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Content-Type','application/json');
  if(req.url==='/api/devices'&&req.method==='GET'){
    const list=Object.values(store.devices).map(d=>({
      imei:d.imei,connected:d.connected||false,lastSeen:d.lastSeen,
      location:d.location||null,status:d.status||null,
      metrics:d.metrics||null,
    }));
    return res.end(JSON.stringify(list));
  }
  if(req.url.startsWith('/api/device/')&&req.method==='GET'){
    const imei=req.url.split('/')[3];
    const dev=store.devices[imei];
    if(!dev){res.statusCode=404;return res.end('{}');}
    return res.end(JSON.stringify({...dev,metrics:metrics[imei]||null}));
  }
  if(req.url==='/api/metrics'&&req.method==='GET'){
    return res.end(JSON.stringify(metrics));
  }
  if(req.url.startsWith('/api/metrics/')&&req.method==='GET'){
    const imei=req.url.split('/')[3];
    return res.end(JSON.stringify(metrics[imei]||{}));
  }
  if(req.url==='/events'){
    res.setHeader('Content-Type','text/event-stream');
    res.setHeader('Cache-Control','no-cache');
    const send=d=>res.write(`data:${JSON.stringify(d)}\n\n`);
    store.events.on('update',send);
    req.on('close',()=>store.events.off('update',send));
    return;
  }
  res.statusCode=404;res.end('not found');
});

server.listen(9000,()=>console.log('[GT06] TCP server on port 9000'));
httpServer.listen(8080,()=>console.log('[HTTP] API on port 8080'));
console.log('[BitValue] Server v2.0 started');
