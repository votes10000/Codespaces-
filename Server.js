require("dotenv").config();
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const app = express();
app.use(express.json());
app.use(cors());

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const jwtSecret = process.env.JWT_SECRET || "your-secret-jwt-key";

const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Helper function to generate JWT
const generateToken = (userId, isAdmin = false) => {
  return jwt.sign({ id: userId, isAdmin }, jwtSecret, { expiresIn: "1h" });
};

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.id;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch (error) {
    res.status(400).json({ error: "Invalid token." });
  }
};

// Client Registration
app.post(
  "/register",
  [
    body("username").notEmpty().trim().isLength({ min: 3 }),
    body("email").isEmail().normalizeEmail(),
    body("password").isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      const { data: existingUser, error: checkError } = await supabase
        .from("users")
        .select("id")
        .or(`username.eq.${username},email.eq.${email}`)
        .single();

      if (checkError) {
        console.error("Error checking existing user:", checkError);
        return res.status(500).json({ error: "Internal server error." });
      }

      if (existingUser) {
        return res.status(409).json({ error: "Username or email already exists." });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const { data: newUser, error: registerError } = await supabase
        .from("users")
        .insert([{ username, email, password_hash: hashedPassword, balance: 0, bonus: 0 }])
        .select("id, username, email")
        .single();

      if (registerError) {
        console.error("Error registering user:", registerError);
        return res.status(500).json({ error: "Failed to register user." });
      }

      const token = generateToken(newUser.id);
      res.status(201).json({ message: "User registered successfully!", user: newUser, token });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ error: "Internal server error during registration." });
    }
  }
);

// Client Login
app.post("/login", async (req, res) => {
  const { identifier, password } = req.body; // Can be username or email

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, username, email, password_hash, is_admin")
      .or(`username.eq.${identifier},email.eq.${identifier}`)
      .single();

    if (userError) {
      console.error("Error during login:", userError);
      return res.status(500).json({ error: "Internal server error." });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = generateToken(user.id, user.is_admin);
    res.json({ message: "Login successful!", token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error during login." });
  }
});

// Admin-only route to update user balance
app.put("/admin/users/:id/balance", verifyToken, async (req, res) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: "Admin privileges required." });
  }

  const { id } = req.params;
  const { balance } = req.body;

  if (typeof balance !== 'number') {
    return res.status(400).json({ error: "Invalid balance value." });
  }

  try {
    const { data: updatedUser, error: updateError } = await supabase
      .from("users")
      .update({ balance })
      .eq("id", id)
      .select("id, username, email, balance, bonus")
      .single();

    if (updateError) {
      console.error("Error updating user balance:", updateError);
      return res.status(500).json({ error: "Failed to update user balance." });
    }

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ message: "User balance updated successfully!", user: updatedUser });
  } catch (error) {
    console.error("Error updating user balance:", error);
    res.status(500).json({ error: "Internal server error during balance update." });
  }
});

// Admin-only route to update user bonus
app.put("/admin/users/:id/bonus", verifyToken, async (req, res) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: "Admin privileges required." });
  }

  const { id } = req.params;
  const { bonus } = req.body;

  if (typeof bonus !== 'number') {
    return res.status(400).json({ error: "Invalid bonus value." });
  }

  try {
    const { data: updatedUser, error: updateError } = await supabase
      .from("users")
      .update({ bonus })
      .eq("id", id)
      .select("id, username, email, balance, bonus")
      .single();

    if (updateError) {
      console.error("Error updating user bonus:", updateError);
      return res.status(500).json({ error: "Failed to update user bonus." });
    }

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ message: "User bonus updated successfully!", user: updatedUser });
  } catch (error) {
    console.error("Error updating user bonus:", error);
    res.status(500).json({ error: "Internal server error during bonus update." });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
