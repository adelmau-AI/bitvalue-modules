'use strict';
const{Pool}=require('pg');
const pool=new Pool({
  host:'172.18.0.3',
  port:5432,
  database:'bitvalue',
  user:'bitvalue_user',
  password:'BitValue2026x',
  max:10,
  idleTimeoutMillis:30000,
});

async function saveTelemetry(imei,gps,status){
  try{
    await pool.query(
      `INSERT INTO telemetry_events(time,imei,lat,lng,speed,course,satellites,gps_fix,acc,engine_on,voltage,gsm,charging,alarm)
       VALUES(NOW(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [imei,gps?.lat||null,gps?.lng||null,gps?.speed||null,gps?.course||null,
       gps?.satellites||null,gps?.located||null,status?.accHigh||null,
       status?.engineOn||null,status?.voltage||null,status?.gsm||null,
       status?.charging||null,status?.alarm||null]
    );
  }catch(e){console.error('[DB] telemetry error:',e.message);}
}

async function saveTrip(imei,trip){
  try{
    await pool.query(
      `INSERT INTO trip_sessions(imei,started_at,ended_at,km,max_speed,avg_speed,hard_braking,hard_accel,driving_score,idle_minutes)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [imei,trip.started_at,trip.ended_at,trip.km,trip.max_speed,
       trip.avg_speed,trip.hard_braking,trip.hard_accel,trip.driving_score,trip.idle_minutes]
    );
  }catch(e){console.error('[DB] trip error:',e.message);}
}

module.exports={saveTelemetry,saveTrip};
