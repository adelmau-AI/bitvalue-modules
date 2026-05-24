t = open('/opt/bitvalue/server.js').read()
t = t.replace(
  "'use strict';",
  "'use strict';\nconst{saveTelemetry,saveTrip}=require('./db.js');"
)
t = t.replace(
  "store.events.emit('update',{imei,...data});",
  "store.events.emit('update',{imei,...data});\n  if(data.location||data.status)saveTelemetry(imei,data.location||dev.location,data.status||dev.status);"
)
t = t.replace(
  "m.trips_today.push({",
  "saveTrip(imei,{started_at:new Date(m.last_acc_on),ended_at:new Date(t),km:parseFloat(m.session_km.toFixed(2)),max_speed:m.speed_max_session,avg_speed:m.speed_count>0?Math.round(m.speed_sum/m.speed_count):0,hard_braking:m.hard_braking,hard_accel:m.hard_accel,driving_score:m.driving_score,idle_minutes:Math.round(m.time_idle/60)});\n      m.trips_today.push({"
)
open('/opt/bitvalue/server.js','w').write(t)
print('OK')
