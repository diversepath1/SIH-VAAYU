// ====== AQI Color Helper ======
function getAQIColor(aqi) {
  if (aqi <= 50) return "#00e400";   // Good
  if (aqi <= 100) return "#ffff00";  // Moderate
  if (aqi <= 150) return "#ff7e00";  // Unhealthy for Sensitive Groups
  if (aqi <= 200) return "#ff0000";  // Unhealthy
  if (aqi <= 300) return "#8f3f97";  // Very Unhealthy
  return "#7e0023";                  // Hazardous
}

// ====== Init Flatpickr ======
if (document.getElementById("datePicker")) {
  const picker = flatpickr("#datePicker", {
    minDate: "today",
    dateFormat: "Y-m-d",
  });
  document.getElementById("calendarIcon").addEventListener("click", () => picker.open());
}

// ====== Init Leaflet Map ======
if (document.getElementById("aqiMap")) {
  const map = L.map("aqiMap").setView([28.6448, 77.216721], 11); // Default Delhi NCR
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19,
  }).addTo(map);

  // Example: one marker from EJS variable (injected into window object)
  if (window.aqiData) {
    L.circleMarker([28.6448, 77.216721], {
      radius: 15,
      fillColor: getAQIColor(window.aqiData.aqi),
      color: "#000",
      weight: 1,
      opacity: 1,
      fillOpacity: 0.8,
    })
      .addTo(map)
      .bindPopup(
        `<b>Current AQI: ${window.aqiData.aqi}</b><br>Major Pollutant: ${window.aqiData.dominantPollutant}`
      );
  }

  // Example: multiple markers if backend passes an array
  if (window.aqiLocations && Array.isArray(window.aqiLocations)) {
    window.aqiLocations.forEach((loc) => {
      L.circleMarker([loc.lat, loc.lng], {
        radius: 12,
        fillColor: getAQIColor(loc.aqi),
        color: "#000",
        weight: 1,
        opacity: 1,
        fillOpacity: 0.8,
      })
        .addTo(map)
        .bindPopup(`<b>${loc.city}</b><br>AQI: ${loc.aqi}<br>Pollutant: ${loc.dominantPollutant}`);
    });
  }
}
