require('dotenv').config();
const express = require("express");
const path = require("path");
const http = require('http');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const expressLayouts = require('express-ejs-layouts');
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const flash = require("connect-flash");

const app = express();
const server = http.createServer(app);

// ===== Middleware =====
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(expressLayouts);
app.set('layout', 'layout/boilerplate');

// ===== MongoDB Connection =====
// =================== DB CONNECTION ===================
mongoose.connect("mongodb://127.0.0.1:27017/wanderlust")
  .then(() => console.log("DB Connected"))
  .catch(err => console.log("DB Error:", err));

const sessionConfig = {
  store: MongoStore.create({ mongoUrl: "mongodb://127.0.0.1:27017/Delhiusers" }),
  secret: "secretcode",
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 },
};
app.use(session(sessionConfig));
app.use(flash());

// ===== User Schema & Model =====
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["citizen", "government", "companies"], default: "citizen" }
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// ===== Auth Middleware =====
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/listings/login");
  }
  next();
}

// ===== Sample AQI & Data =====
const sampleAQI = { city: "Delhi", aqi: 180, dominantPollutant: "PM2.5", temp: 32, humidity: 50 };
const multipleLocations = [
  { city: "Delhi", lat: 28.6448, lng: 77.216721, aqi: 180, dominantPollutant: "PM2.5" },
  { city: "Noida", lat: 28.5355, lng: 77.3910, aqi: 150, dominantPollutant: "PM10" },
  { city: "Gurugram", lat: 28.4595, lng: 77.0266, aqi: 120, dominantPollutant: "O3" },
];
const touristSpots = [
  { name: "India Gate", lat: 28.6129, lng: 77.2295 },
  { name: "Red Fort", lat: 28.6562, lng: 77.2410 },
  { name: "Qutub Minar", lat: 28.5244, lng: 77.1855 },
];

const policies = [
  { name: "Odd-Even Vehicle Rule", implemented: true },
  { name: "Industrial Emission Control", implemented: true },
  { name: "Construction Dust Control", implemented: false },
];
const products = [
  { name: "EV Incentive Program", desc: "Promoting electric vehicles" },
  { name: "Green Delhi Plantation Drive", desc: "Urban greening initiative" },
  { name: "Industrial Scrubber Upgrade", desc: "Reducing factory emissions" },
];
const statsSummary = {
  totalUsers: 1250,
  totalCompanies: 40,
  activePolicies: policies.filter(p => p.implemented).length
};

// ===== Helper Functions =====
function getEdgeWeight(edge, alpha = 1, beta = 1, gamma = 1, preferScenic = false) {
  return alpha * edge.aqi + beta * edge.distance + (preferScenic ? -gamma * edge.tourist : 0);
}
function dijkstra(graph, start, end, alpha, beta, gamma, preferScenic) {
  const distances = {}, prev = {}, pq = new Set(Object.keys(graph));
  Object.keys(graph).forEach(n => distances[n] = Infinity);
  distances[start] = 0;
  while (pq.size) {
    const u = [...pq].reduce((min, node) => distances[node] < distances[min] ? node : min, [...pq][0]);
    pq.delete(u);
    if (u === end) break;
    graph[u].forEach(edge => {
      const alt = distances[u] + getEdgeWeight(edge, alpha, beta, gamma, preferScenic);
      if (alt < distances[edge.to]) { distances[edge.to] = alt; prev[edge.to] = u; }
    });
  }
  const path = [];
  let u = end;
  while (prev[u]) { path.unshift(u); u = prev[u]; }
  if (u === start) path.unshift(start);
  return path;
}
function getHealthRecommendation(aqi, age, symptoms, experience) {
  const alerts = [];
  if (aqi > 100 || experience === 'high') alerts.push("⚠️ Wear an N95 mask outdoors");
  if (aqi > 150) alerts.push("🏠 Limit outdoor activity, stay indoors");
  if (symptoms?.includes("asthma") || symptoms?.includes("heart")) alerts.push("💨 Avoid strenuous outdoor activity");
  if (aqi > 200) alerts.push("🔴 Use indoor air purifier if available");
  return alerts.length ? alerts : ["✅ Air quality is good"];
}

// ===== Routes =====
app.get("/", (req, res) => res.redirect("/dashboard"));

app.get("/dashboard", requireLogin, (req, res) => {
  const apiKey = process.env.AQICN_API_KEY || "YOUR_API_KEY";
  res.render("dashboard", { aqiData: sampleAQI, aqiLocations: multipleLocations, touristSpots, apiKey });
});
app.get('/views/citizen', (req, res) => {
  res.render('citizen'); // No need for .ejs extension
});
app.get("/policy", requireLogin, (req, res) => res.render("policy", { policies, products, statsSummary }));

app.post("/api/citizen-route", (req, res) => {
  const { source, destination, preferScenic, age, symptoms, experience } = req.body;
  const graph = {
    A: [{ to: 'B', distance: 2, aqi: 120, tourist: 5 }, { to: 'C', distance: 3, aqi: 200, tourist: 0 }],
    B: [{ to: 'C', distance: 2, aqi: 100, tourist: 10 }, { to: 'D', distance: 4, aqi: 150, tourist: 2 }],
    C: [{ to: 'D', distance: 2, aqi: 80, tourist: 7 }],
    D: []
  };
  const coords = { A: [28.6139, 77.2090], B: [28.62, 77.21], C: [28.63, 77.22], D: [28.64, 77.23] };
  const route = dijkstra(graph, source, destination, 1, 1, 1, preferScenic);
  const alerts = getHealthRecommendation(sampleAQI.aqi, age, symptoms, experience);
  const pathLatLng = route.map(n => coords[n]);
  res.json({ route, pathLatLng, alerts });
});

// ===== Auth Routes =====

// 📝 Register
app.get("/listings/register", (req, res) => res.render("listings/register"));

app.post("/listings/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.send("⚠️ Email already registered");

    const user = new User({ username, email, password, role });
    await user.save();
    req.session.userId = user._id;
    res.redirect("/dashboard");
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).send("Error registering user");
  }
});

// 🔐 Login
app.get("/listings/login", (req, res) => res.render("listings/login"));

app.post("/listings/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    // Try finding by username or email
    const user = await User.findOne({
      $or: [{ username: identifier }, { email: identifier }]
    });

    if (!user) return res.send("❌ User not found");

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.send("❌ Invalid password");

    req.session.userId = user._id;
    res.redirect("/dashboard");
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).send("Error logging in");
  }
});


// 🚪 Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/listings/login"));
});

// ===== Start Server =====
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🌍 Server running at http://localhost:${PORT}`));
