// server.js (or your main application file)
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Secret key for JWT (store securely in environment variables)
const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';

// --- Helper Functions ---

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, jwtSecret, { expiresIn: '1h' }); // Token expires in 1 hour
};

const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1]; // Get token from Authorization header

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.userId = decoded.id;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};

// --- API Endpoints ---

// 1. Client Registration
app.post(
    '/api/register',
    [
        body('username').notEmpty().trim().isLength({ min: 3 }),
        body('email').isEmail().normalizeEmail(),
        body('password').isLength({ min: 6 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            // Check if the username or email already exists
            const { data: existingUser, error: existingUserError } = await supabase
                .from('users')
                .select('*')
                .or(`username.eq.${username},email.eq.${email}`)
                .single();

            if (existingUserError) {
                console.error('Error checking existing user:', existingUserError);
                return res.status(500).json({ error: 'Internal server error.' });
            }

            if (existingUser) {
                if (existingUser.username === username) {
                    return res.status(409).json({ error: 'Username already taken.' });
                }
                if (existingUser.email === email) {
                    return res.status(409).json({ error: 'Email already registered.' });
                }
            }

            // Hash the password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Insert the new user into the database
            const { data: newUser, error: insertError } = await supabase
                .from('users')
                .insert([
                    { username, email, password_hash: hashedPassword }
                ])
                .select()
                .single();

            if (insertError) {
                console.error('Error registering user:', insertError);
                return res.status(500).json({ error: 'Failed to register user.' });
            }

            // Generate a JWT token for the newly registered user
            const token = generateToken(newUser.id);

            res.status(201).json({ message: 'User registered successfully!', user: { id: newUser.id, username: newUser.username, email: newUser.email }, token });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ error: 'Internal server error during registration.' });
        }
    }
);

// 2. Get User Data (Requires Authentication)
app.get('/api/users/:id', verifyToken, async (req, res) => {
    const userId = parseInt(req.params.id);

    // Ensure the requested user ID matches the authenticated user's ID
    if (userId !== req.userId) {
        return res.status(403).json({ error: 'Unauthorized to access this user data.' });
    }

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, username, email, created_at, updated_at')
            .eq('id', userId)
            .single();

        if (error) {
            console.error('Error fetching user data:', error);
            return res.status(500).json({ error: 'Failed to fetch user data.' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.status(200).json(user);
    } catch (error) {
        console.error('Error getting user data:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// 3. Edit User Data (Requires Authentication)
app.put(
    '/api/users/:id',
    verifyToken,
    [
        body('username').optional().trim().isLength({ min: 3 }),
        body('email').optional().isEmail().normalizeEmail(),
        body('password').optional().isLength({ min: 6 }),
    ],
    async (req, res) => {
        const userId = parseInt(req.params.id);

        // Ensure the requested user ID matches the authenticated user's ID
        if (userId !== req.userId) {
            return res.status(403).json({ error: 'Unauthorized to edit this user data.' });
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;
        const updates = {};

        if (username) {
            updates.username = username;
        }
        if (email) {
            updates.email = email;
        }
        if (password) {
            const salt = await bcrypt.genSalt(10);
            updates.password_hash = await bcrypt.hash(password, salt);
        }
        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: 'No update data provided.' });
        }

        updates.updated_at = new Date().toISOString();

        try {
            // Check if the new username or email (if provided) already exists for other users
            if (username || email) {
                const { data: existingUser, error: existingUserError } = await supabase
                    .from('users')
                    .select('*')
                    .or(`username.eq.${username || ''},email.eq.${email || ''}`)
                    .not('id', 'eq', userId)
                    .single();

                if (existingUserError) {
                    console.error('Error checking existing user:', existingUserError);
                    return res.status(500).json({ error: 'Internal server error.' });
                }

                if (existingUser) {
                    if (existingUser.username === username) {
                        return res.status(409).json({ error: 'Username already taken.' });
                    }
                    if (existingUser.email === email) {
                        return res.status(409).json({ error: 'Email already registered.' });
                    }
                }
            }

            const { data: updatedUser, error: updateError } = await supabase
                .from('users')
                .update(updates)
                .eq('id', userId)
                .select('id, username, email, created_at, updated_at')
                .single();

            if (updateError) {
                console.error('Error updating user:', updateError);
                return res.status(500).json({ error: 'Failed to update user data.' });
            }

            if (!updatedUser) {
                return res.status(404).json({ error: 'User not found.' });
            }

            res.status(200).json({ message: 'User data updated successfully!', user: updatedUser });

        } catch (error) {
            console.error('Error updating user data:', error);
            res.status(500).json({ error: 'Internal server error during user data update.' });
        }
    }
);

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
