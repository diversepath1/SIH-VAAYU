// ===== Dummy AQI value for now =====
let dummyAQI = 150; // change as needed

function getAQICategory(aqi) {
  if (aqi <= 50) return { key: 'Good', cls: 'aqi-good', advice: 'Air quality is satisfactory.' };
  if (aqi <= 100) return { key: 'Moderate', cls: 'aqi-moderate', advice: 'Acceptable; sensitive people should limit exertion.' };
  if (aqi <= 150) return { key: 'Unhealthy for Sensitive Groups', cls: 'aqi-usg', advice: 'Sensitive groups should reduce outdoor activity.' };
  if (aqi <= 200) return { key: 'Unhealthy', cls: 'aqi-unhealthy', advice: 'Everyone may feel health effects.' };
  if (aqi <= 300) return { key: 'Very Unhealthy', cls: 'aqi-veryunhealthy', advice: 'Health alert: serious effects for everyone.' };
  return { key: 'Hazardous', cls: 'aqi-hazardous', advice: 'Emergency conditions. Avoid all outdoor exertion.' };
}

function buildPersonalizedMessage(age, conditions, categoryKey) {
  let msg = '';
  const vulnerable = (age <= 12 || age >= 65) || conditions.length > 0;

  if (vulnerable) msg += '⚠️ You are in a higher-risk group. ';
  else msg += '🙂 You are in a typical-risk group. ';

  if (conditions.includes('asthma')) msg += 'Asthma detected — avoid strenuous activity outdoors. ';
  if (conditions.includes('heart')) msg += 'Heart condition — avoid exertion outdoors. ';
  if (conditions.includes('diabetes')) msg += 'Diabetes — extra care during high pollution. ';

  return msg;
}

function renderHealthWidget(aqi) {
  const age = parseInt(document.getElementById('hw-age').value) || 30;
  const checked = Array.from(document.querySelectorAll('.hw-checkboxes input:checked')).map(c => c.value);
  const conds = checked.includes('none') ? [] : checked;

  const category = getAQICategory(aqi);

  document.getElementById('hw-aqi-display').innerHTML =
    `<strong>AQI:</strong> ${aqi} <span class="${category.cls}">(${category.key})</span>`;
  document.getElementById('hw-warning').textContent = category.advice;
  document.getElementById('hw-personalized').textContent = buildPersonalizedMessage(age, conds, category.key);
  document.getElementById('hw-actions').innerHTML = `<em>Recommendation:</em> Stay indoors if possible when AQI is ${category.key}.`;
}

// Button listener
document.getElementById('hw-update-btn').addEventListener('click', () => {
  renderHealthWidget(dummyAQI);
});

// Initial render with dummy data
renderHealthWidget(dummyAQI);
