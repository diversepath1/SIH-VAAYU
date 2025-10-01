// ===== Leaflet Map Initialization =====
const routeMap = L.map('routeMap').setView([28.6139, 77.2090], 12);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(routeMap);

// ===== Dummy AQI Data =====
const stationData = [
  { name: "Jawaharlal Nehru Stadium", city: { geo: [28.6139,77.2090] }, aqi: 180, dominentpol: "pm2.5" },
  { name: "ITI Jahangirpuri", city: { geo: [28.70,77.16] }, aqi: 150, dominentpol: "pm2.5" },
  { name: "Mandir Marg", city: { geo: [28.62,77.23] }, aqi: 120, dominentpol: "pm10" },
  { name: "Punjabi Bagh", city: { geo: [28.65,77.15] }, aqi: 200, dominentpol: "pm2.5" },
  { name: "R.K. Puram", city: { geo: [28.58,77.18] }, aqi: 90, dominentpol: "no2" }
];
const localCityData = stationData[0]; // Treat first station as "local city"

// ===== Graph & Routes =====
const graph = {
  A:[{to:'B',distance:2,tourist:5,aqi:180},{to:'C',distance:3,tourist:0,aqi:200}],
  B:[{to:'C',distance:2,tourist:10,aqi:150},{to:'D',distance:4,tourist:2,aqi:120}],
  C:[{to:'D',distance:2,tourist:7,aqi:80}],
  D:[]
};
const coords = {A:[28.6139,77.2090], B:[28.62,77.21], C:[28.63,77.22], D:[28.64,77.23]};

// ===== Tourist Spots =====
const touristSpots = [
  {name:"India Gate",lat:28.6129,lng:77.2295},
  {name:"Red Fort",lat:28.6562,lng:77.2410},
  {name:"Qutub Minar",lat:28.5244,lng:77.1855}
];
touristSpots.forEach(spot => {
  L.marker([spot.lat,spot.lng]).addTo(routeMap).bindPopup(`<b>${spot.name}</b>`);
});

// ===== Utility Functions =====
function getAQIColor(aqi){
  if(aqi<=50) return 'green';
  else if(aqi<=100) return 'yellow';
  else if(aqi<=150) return 'orange';
  else if(aqi<=200) return 'red';
  else if(aqi<=300) return 'purple';
  else return 'maroon';
}

function getEdgeWeight(edge, alpha=1, beta=1, gamma=1, preferScenic=false){
  return alpha*edge.aqi + beta*edge.distance + (preferScenic?-gamma*edge.tourist:0);
}

// ===== Dijkstra Algorithm =====
function dijkstra(graph,start,end,alpha,beta,gamma,preferScenic){
  const distances={}, prev={}, pq=new Set(Object.keys(graph));
  Object.keys(graph).forEach(n=>distances[n]=Infinity);
  distances[start]=0;

  while(pq.size){
    const u=[...pq].reduce((min,node)=>distances[node]<distances[min]?node:min,[...pq][0]);
    pq.delete(u);
    if(u===end) break;

    graph[u].forEach(edge=>{
      const alt = distances[u]+getEdgeWeight(edge,alpha,beta,gamma,preferScenic);
      if(alt<distances[edge.to]){
        distances[edge.to]=alt;
        prev[edge.to]=u;
      }
    });
  }

  // Reconstruct path
  const path=[]; let u=end;
  while(prev[u]){ path.unshift(u); u=prev[u]; }
  if(u===start) path.unshift(start);
  return path;
}

// ===== Health Alerts =====
function getHealthRecommendation(aqi, age, symptoms, experience){
  const alerts=[];
  if(aqi>100 || experience==='high') alerts.push("⚠️ Consider wearing an N95 mask outdoors");
  if(aqi>150) alerts.push("🏠 Limit outdoor activity, stay indoors if possible");
  if(symptoms.includes("asthma")||symptoms.includes("heart")) alerts.push("💨 Avoid strenuous outdoor activity");
  if(aqi>200) alerts.push("🔴 Use indoor air purifier if available");
  return alerts.length?alerts:["✅ Air quality is good"];
}
function showHealthAlerts(alerts){
  const el=document.getElementById('healthAlerts'); el.innerHTML="";
  alerts.forEach(a=>{
    const li=document.createElement('li');
    li.textContent=a;
    li.classList.add("list-group-item");
    el.appendChild(li);
  });
}

// ===== Handle Calculate Route =====
document.getElementById('calculateRouteBtn').addEventListener('click',()=>{
  const source=document.getElementById('source').value||'A';
  const destination=document.getElementById('destination').value||'D';
  const travelMode=document.getElementById('travelMode').value;
  const preferScenic=document.getElementById('preferScenic').checked;

  const alpha=1, beta=1, gamma=1; // can adjust based on travelMode
  const route=dijkstra(graph,source,destination,alpha,beta,gamma,preferScenic);

  // Clear previous route
  routeMap.eachLayer(l=>{if(l instanceof L.Polyline) routeMap.removeLayer(l);});

  // Draw route
  const pathLatLng=route.map(n=>coords[n]);
  L.polyline(pathLatLng,{color:'green',weight:5,opacity:0.7}).addTo(routeMap);

  // Show health alerts based on local AQI (dummy)
  const userAge=30; const userSymptoms=['asthma']; const experience='high';
  const currentAQI=localCityData.aqi;
  showHealthAlerts(getHealthRecommendation(currentAQI,userAge,userSymptoms,experience));
});

