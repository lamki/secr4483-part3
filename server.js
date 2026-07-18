const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Enhancements: HTTP Headers protection
app.use(helmet());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection Configuration
const pool = mysql.createPool({
    host: 'localhost',
    user: 'admin',
    // password: 'Secure_Password123!',
    database: 'secure_app',
    waitForConnections: true,
    connectionLimit: 10
});

// Secure Session Management Configuration
app.use(session({
    secret: 'super_secret_session_key_32_bytes_long!',
    resave: false,
    saveUninitialized: false,
    name: '__Host-SessionID', // Prevents session cookie tampering
    cookie: {
        httpOnly: true, // Mitigates XSS cookie theft
        secure: false,  // Set to true if running over local HTTPS
        sameSite: 'strict', // Mitigates CSRF
        maxAge: 15 * 60 * 1000 // 15-minute Session Timeout
    }
}));

// Authorization Middleware (RBAC)
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    return res.status(401).json({ error: "Unauthorized access. Please log in." });
}

function hasRole(role) {
    return (req, res, next) => {
        if (req.session.role === role) {
            return next();
        }
        return res.status(403).json({ error: "Forbidden: Insufficient permissions." });
    };
}

// --- AUTHENTICATION MODULE ---

// Secure Registration Endpoint
app.post('/api/register', [
    body('username').trim().isAlphanumeric().isLength({ min: 4, max: 20 }),
    body('password').isLength({ min: 8 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: "Invalid registration parameters syntax." });
    }

    const { username, password } = req.body;
    try {
        // Encrypted storage check and hashing
        const [existing] = await pool.execute('SELECT id FROM users WHERE username = ?', [username]);
        if (existing.length > 0) {
            return res.status(409).json({ error: "Username already registered." });
        }

        const saltRounds = 12;
        const hash = await bcrypt.hash(password, saltRounds);
        
        await pool.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, 'user']);
        return res.status(201).json({ message: "User registered successfully." });
    } catch (err) {
        // Proper Error Handling without revealing stack traces
        return res.status(500).json({ error: "Internal server error occurred." });
    }
});

// Secure Login Endpoint with Session ID Regeneration
app.post('/api/login', [
    body('username').trim().escape()
], async (req, res) => {
    const { username, password } = req.body;
    try {
        // Parameterized Query eliminates SQL Injection
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) {
            return res.status(401).json({ error: "Invalid username or password." });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: "Invalid username or password." });
        }

        // Prevent Session Fixation via Regeneration
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ error: "Session creation error." });
            
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            
            return res.json({ message: "Login successful.", role: user.role });
        });
    } catch (err) {
        return res.status(500).json({ error: "Internal processing failure." });
    }
});

// --- TRANSACTION MODULE ---

// Secure Transaction Fetching (Authorization Gaps Closed)
app.get('/api/transactions', isAuthenticated, async (req, res) => {
    try {
        // Strictly scopes queries to the session-identified individual
        const [rows] = await pool.execute('SELECT id, amount, description, transaction_date FROM transactions WHERE user_id = ?', [req.session.userId]);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: "Failed to retrieve records." });
    }
});

// Secure Transaction Submission (Input Protection & Sanitization)
app.post('/api/transactions', isAuthenticated, [
    body('amount').isFloat({ min: 0.01 }),
    body('description').trim().isLength({ min: 1, max: 255 }).escape() // Escapes output data to prevent persistent XSS
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: "Invalid transaction data fields." });
    }

    const { amount, description } = req.body;
    try {
        await pool.execute('INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)', [req.session.userId, amount, description]);
        return res.status(201).json({ message: "Transaction processed securely." });
    } catch (err) {
        return res.status(500).json({ error: "Transaction commitment failure." });
    }
});

// Logout Endpoint
app.post('/api/logout', isAuthenticated, (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: "Logout failed." });
        res.clearCookie('__Host-SessionID');
        return res.json({ message: "Logged out successfully." });
    });
});

app.listen(PORT, () => console.log(`Secure integrated runtime activated on port ${PORT}`));