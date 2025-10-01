// ======= dashboard.js =======

// Flatpickr initialization
const dateInput = document.getElementById('datePicker');
flatpickr("#datePicker", {
  dateFormat: "Y-m-d",
  defaultDate: new Date()
});

// Open Flatpickr when calendar icon is clicked
document.getElementById('calendarIcon').addEventListener('click', () => {
  dateInput._flatpickr.open();
});

// Initialize Leaflet map
const map = L.map('aqiMap').setView([28.6139, 77.2090], 11);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

// Multiple AQI stations in Delhi
const stations = [
  { id: 'A79471', name: 'Jawaharlal Nehru Stadium, Delhi' },
  { id: 'A79472', name: 'ITI Jahangirpuri, Delhi' },
  { id: 'A79473', name: 'Mandir Marg, Delhi' },
  { id: 'A79474', name: 'Punjabi Bagh, Delhi' },
  { id: 'A79475', name: 'R.K. Puram, Delhi' }
];

const apiKey = 'YOUR_API_KEY'; // Replace with your AQICN API key

// Fetch AQI data and add markers
stations.forEach(station => {
  fetch(`https://api.waqi.info/feed/${station.id}/?token=${apiKey}`)
    .then(resp => resp.json())
    .then(data => {
      if (data.status === 'ok') {
        const { aqi, city: { geo } } = data.data;
        const [lat, lon] = geo;

        // Color-coded markers based on AQI
        let color;
        if (aqi <= 50) color = 'green';
        else if (aqi <= 100) color = 'yellow';
        else if (aqi <= 150) color = 'orange';
        else if (aqi <= 200) color = 'red';
        else if (aqi <= 300) color = 'purple';
        else color = 'maroon';

        // Add circle marker
        L.circleMarker([lat, lon], {
          color,
          fillColor: color,
          fillOpacity: 0.5,
          radius: 10
        })
        .addTo(map)
        .bindPopup(`${station.name}<br>AQI: <strong>${aqi}</strong>`);
      }
    })
    .catch(err => console.error('Error fetching AQI data:', err));
});

// ===== Module Filter Logic =====
const moduleButtons = document.querySelectorAll('.module-btn');
moduleButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const module = btn.dataset.module;

    // Hide all module content
    document.querySelectorAll('.module-content').forEach(div => {
      div.classList.remove('active');
    });

    // Show selected module
    document.getElementById(module).classList.add('active');
  });
});
