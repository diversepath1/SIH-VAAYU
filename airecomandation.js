// airecomandation.js
// Dummy AI + rule-based recommendation

// Haversine distance
function haversineDistance(coord1, coord2) {
  const R = 6371;
  const dLat = deg2rad(coord2.lat - coord1.lat);
  const dLon = deg2rad(coord2.lon - coord1.lon);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(deg2rad(coord1.lat)) *
    Math.cos(deg2rad(coord2.lat)) *
    Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
function deg2rad(deg) { return deg * (Math.PI / 180); }

// Rule-based AI
function ruleBasedRecommendation(sensor) {
  const { aqi, pollutant, lat, lon } = sensor;
  let source = "Normal", action = "No action needed";

  if (aqi > 250) { source = "Industrial"; action = "Restrict vehicles"; }
  else if (aqi > 180) { source = "Crop Burning"; action = "Issue alerts"; }
  else if (["SO2","NO2"].includes(pollutant)) { source = "Forest Fire"; action = "Alert forest dept"; }
  else if (aqi > 100) { source = "Traffic"; action = "Reroute vehicles"; }

  // Protect monuments if nearby
  const monuments = [
    { name: "Taj Mahal", lat:27.1751, lon:78.0421 },
    { name: "India Gate", lat:28.6129, lon:77.2295 }
  ];
  monuments.forEach(mon => {
    const dist = haversineDistance({ lat, lon }, { lat: mon.lat, lon: mon.lon });
    if (dist < 5 && aqi > 150) action += ` | ALERT: Protect ${mon.name}`;
  });

  return { source, action };
}

// Hybrid recommendation (dummy ML call fallback)
async function getRecommendation(sensor) {
  try {
    // Simulate ML API call
    // throw new Error("ML unavailable"); // uncomment to simulate fallback
    return ruleBasedRecommendation(sensor);
  } catch (err) {
    return ruleBasedRecommendation(sensor);
  }
}

module.exports = { getRecommendation };
