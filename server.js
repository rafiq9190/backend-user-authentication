const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
app.use(cors());
const PORT = 3000;
const JWT_SECRET = jwt.sign({ foo: "bar" }, "shhhhh");
const usersFilePath = path.join(__dirname, "users.json");

app.use(bodyParser.json());

// Load users from JSON file
const loadUsers = () => {
  if (!fs.existsSync(usersFilePath)) {
    fs.writeFileSync(usersFilePath, JSON.stringify([]));
  }
  return JSON.parse(fs.readFileSync(usersFilePath));
};

// Save users to JSON file
const saveUsers = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) return res.sendStatus(403);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Register user
app.post("/register", async (req, res) => {
  const { username, email, password, role } = req.body;
  const users = loadUsers();
  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(400).send("User already exists");
  }
  // Generate token for the newly registered user
  const token = jwt.sign({ username, email, password, role }, JWT_SECRET, {
    expiresIn: "1h",
  });
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashedPassword, role });
  saveUsers(users);
  res.status(201).json({
    message: "User registered",
    token,
    role,
    username,
  });
});

// Login user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user = users.find((u) => u.email === email);

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign(
      { email: user.email, role: user.role, username: user.username },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    res.json({ token, role: user.role, name: user.username });
  } else {
    res.send("Username or password incorrect");
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
