const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const users = []; 
const ACCESS_SECRET = "3mtt_access_key";
const REFRESH_SECRET = "3mtt_refresh_key";
let refreshTokens = [];

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (users.find(u => u.email === email)) return res.status(409).send("Email exists");
  const hash = await bcrypt.hash(password, 10);
  users.push({ email, password: hash, role: "user" });
  res.status(201).send("User registered");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).send("Invalid");
  const accessToken = jwt.sign({ email, role: user.role }, ACCESS_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ email }, REFRESH_SECRET, { expiresIn: "7d" });
  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
});

app.post("/refresh", (req, res) => {
  const { token } = req.body;
  if (!token || !refreshTokens.includes(token)) return res.sendStatus(403);
  jwt.verify(token, REFRESH_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = jwt.sign({ email: user.email }, ACCESS_SECRET, { expiresIn: "15m" });
    res.json({ accessToken });
  });
});

app.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).send("User not found");
  user.password = await bcrypt.hash(newPassword, 10);
  res.send("Password reset");
});
const authenticate = (req, res, next) => {
  const auth = req.headers["authorization"];
  const token = auth && auth.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, ACCESS_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const requireRole = (role) => (req, res, next) => {
  if (req.user.role!== role) return res.sendStatus(403);
  next();
};

app.get("/admin", authenticate, requireRole("admin"), (req, res) => {
  res.send("Welcome admin");
});

app.listen(3000, () => console.log("Server on 3000"));
         
  });
app.post("/logout", (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter(t => t!== token); 
  res.send("Logged out");
});
