require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());
app.use(cors());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const jwtSecret = process.env.JWT_SECRET || "supersecretkey";

// Generate JWT
const generateToken = (userId, isAdmin = false) =>
  jwt.sign({ id: userId, isAdmin }, jwtSecret, { expiresIn: "2h" });

// Verify JWT middleware
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided." });

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.id;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token." });
  }
};

// Register
app.post("/register",
  [
    body("username").notEmpty().isLength({ min: 3 }),
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, email, password } = req.body;

    const { data: existingUser } = await supabase
      .from("users")
      .select("id")
      .or(`username.eq.${username},email.eq.${email}`)
      .maybeSingle();

    if (existingUser) return res.status(409).json({ error: "User already exists." });

    const password_hash = await bcrypt.hash(password, 10);

    const { data: newUser, error } = await supabase
      .from("users")
      .insert([{ username, email, password_hash, balance: 0, bonus: 0 }])
      .select("id, username, email")
      .single();

    if (error) return res.status(500).json({ error: "Registration failed." });

    const token = generateToken(newUser.id);
    res.json({ user: newUser, token });
  }
);

// Login
app.post("/login",
  [
    body("identifier").notEmpty().isLength({ min: 3 }),
    body("password").isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { identifier, password } = req.body;

    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, email, password_hash, is_admin")
      .or(`username.eq.${identifier},email.eq.${identifier}`)
      .maybeSingle();

    if (error || !user) return res.status(401).json({ error: "Invalid credentials." });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials." });

    const token = generateToken(user.id, user.is_admin);
    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, username: user.username, email: user.email },
    });
  }
);

// Admin: Update balance
app.put("/admin/users/:id/balance", verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ error: "Admin only." });

  const { id } = req.params;
  const { balance } = req.body;

  if (typeof balance !== "number") return res.status(400).json({ error: "Balance must be a number." });

  const { data, error } = await supabase
    .from("users")
    .update({ balance })
    .eq("id", id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: "Failed to update balance." });

  res.json({ message: "Balance updated", user: data });
});

// Admin: Update bonus
app.put("/admin/users/:id/bonus", verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ error: "Admin only." });

  const { id } = req.params;
  const { bonus } = req.body;

  if (typeof bonus !== "number") return res.status(400).json({ error: "Bonus must be a number." });

  const { data, error } = await supabase
    .from("users")
    .update({ bonus })
    .eq("id", id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: "Failed to update bonus." });

  res.json({ message: "Bonus updated", user: data });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
