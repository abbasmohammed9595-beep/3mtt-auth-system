    const express = require("express");
    const bcrypt = require("bcrypt");
    const jwt = require("jsonwebtoken");
    const app = express();
    app.use(express.json());

    const users = []; 
    const ACCESS_SECRET = "3mtt_access_key";

    app.post("/register", async (req, res) => {
      const { email, password } = req.body;
      const hash = await bcrypt.hash(password, 10);
      users.push({ email, password: hash });
      res.status(201).send("User registered");
    });

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      const user = users.find(u => u.email === email);
      if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).send("Invalid");
      const token = jwt.sign({ email }, ACCESS_SECRET, { expiresIn: "15m" });
      res.json({ accessToken: token });
    });

    app.listen(3000, () => console.log("Server on 3000"));
