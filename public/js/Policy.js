<script>
// Sample policies (from server)
const policies = <%- JSON.stringify(policies) %>;

// Generate hourly emissions dynamically
const hours = Array.from({length: 24}, (_, i) => i + ":00");
const emissionsWithPolicy = [];
const emissionsWithoutPolicy = [];

// Base emission level
let baseEmission = 100;

// Simulate emission trends over 24 hours
hours.forEach((h, i) => {
  let reductionFactor = policies.filter(p=>p.implemented).length / policies.length; // more policies implemented => lower emissions
  let increaseFactor = policies.filter(p=>!p.implemented).length / policies.length; // more unimplemented => higher emissions

  // Emission if policy implemented
  let withPolicy = baseEmission * (1 - 0.2 * reductionFactor) + Math.random() * 10;
  emissionsWithPolicy.push(Math.round(withPolicy));

  // Emission if policy NOT implemented
  let withoutPolicy = baseEmission * (1 + 0.2 * increaseFactor) + Math.random() * 10;
  emissionsWithoutPolicy.push(Math.round(withoutPolicy));

  baseEmission += 2; // gradual increase to simulate urban pollution
});

// Chart.js
const ctx = document.getElementById('emissionChart').getContext('2d');
new Chart(ctx, {
  type: 'line',
  data: {
    labels: hours,
    datasets: [
      { label: 'With Policy', data: emissionsWithPolicy, borderColor: 'green', fill:false, tension:0.3 },
      { label: 'Without Policy', data: emissionsWithoutPolicy, borderColor: 'red', fill:false, tension:0.3 }
    ]
  },
  options: {
    responsive:true,
    plugins:{ legend:{position:'top'}, title:{display:true,text:'Hourly Emission Levels'} },
    scales:{ y:{ title:{display:true,text:'Emission Level (μg/m³)'} }, x:{ title:{display:true,text:'Hour of Day'} } }
  }
});
</script>
