const express = require('express');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS

const SUPABASE_URL = 'https://ufsuproibzksvcfhxvdg.supabase.co';
const SUPABASE_API_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVmc3Vwcm9pYnprc3ZjZmh4dmRnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDQyMjEwMzgsImV4cCI6MjA1OTc5NzAzOH0.GQI0R2FTPN0Qg6u0O8-l0mVBuuUoo22jNqY15wLRAqk';

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const response = await axios.post(
      `${SUPABASE_URL}/rest/v1/users`,
      { email, password_hash: hash },
      {
        headers: {
          'apikey': SUPABASE_API_KEY,
          'Authorization': `Bearer ${SUPABASE_API_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation'
        }
      }
    );
x  } catch (error) {
    res.status(400).json({ error: error.response.data });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const response = await axios.get(
      `${SUPABASE_URL}/rest/v1/users?email=eq.${email}`,
      {
        headers: {
          'apikey': SUPABASE_API_KEY,
          'Authorization': `Bearer ${SUPABASE_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const user = response.data[0];
    if (!user) return res.status(401).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });

    res.status(200).json({ success: true, message: 'Login successful' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on port 3000');
});
