require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Database Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: true }
});

// Authentication Middleware (Protects routes & enforces multi-tenancy)
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(403).json({ error: "Access Denied" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user; // Contains { id, company_id, role, subscription_status }
        
        // Subscription Logic check
        if (req.user.subscription_status === 'unpaid_lockout') {
            return res.status(403).json({ error: "Account locked. Please pay your subscription." });
        }
        next();
    });
};

app.post('/api/policies/create', authenticateToken, async (req, res) => {
    const { type, hName, hID, hContact, hAddress, bName, bID } = req.body;
    const companyId = req.user.company_id; // Taken from JWT
    const policyNo = 'POL' + Math.floor(Math.random() * 1000000);

    try {
        await db.execute(
            `INSERT INTO policies (company_id, policy_no, policy_type, holder_name, holder_id_number, holder_contact, holder_address, beneficiary_name, beneficiary_id_number) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, policyNo, type, hName, hID, hContact, hAddress, bName, bID]
        );
        res.status(201).json({ message: "Policy Created" });
    } catch (err) {
        res.status(500).json({ error: "Database error" });
    }
});
// --- NEW POLICY ROUTE (Fixes the 404 Error) ---
app.post('/api/policies/create', authenticateJWT, async (req, res) => {
    const { type, hName, hID, hContact, hAddress, bName, bID, bContact, bAddress, dob } = req.body;
    const company_id = req.user.company_id;
    
    // Auto-generate a unique policy number
    const policy_no = `POL-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    try {
        await db.execute(
            `INSERT INTO policies (company_id, policy_no, policy_type, holder_name, holder_id_number, 
             holder_contact, holder_address, holder_dob, beneficiary_name, beneficiary_id_number, 
             beneficiary_contact, beneficiary_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policy_no, type, hName, hID, hContact, hAddress, dob, bName, bID, bContact, bAddress]
        );
        res.json({ success: true, policy_no });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to create policy." });
    }
});

// --- GET COMPANY INFO (For Self-Service Link) ---
app.get('/api/company-info', authenticateJWT, async (req, res) => {
    const [rows] = await db.execute('SELECT id, name, has_self_service FROM companies WHERE id = ?', [req.user.company_id]);
    res.json(rows[0]);
});

        // 2. Create Admin User
        await db.execute(
            'INSERT INTO users (company_id, username, password_hash, role) VALUES (?, ?, ?, ?)',
            [companyId, username, hashedPassword, 'admin']
        );

        res.json({ success: true, company_id: companyId });
    } catch (err) {
        res.status(500).json({ error: "Username already exists or database error" });
    }
});
// -----------------------------------------
// ROUTE: Login
// -----------------------------------------
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [users] = await db.execute(
            `SELECT u.*, c.subscription_status, c.has_self_service 
             FROM users u 
             JOIN companies c ON u.company_id = c.id 
             WHERE u.username = ?`, 
            [username]
        );

        if (users.length === 0) return res.status(401).json({ error: "User not found" });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: "Invalid password" });

        // Generate Token with Company ID (Critical for isolating data)
        const token = jwt.sign(
            { id: user.id, company_id: user.company_id, role: user.role, subscription_status: user.subscription_status },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ token, role: user.role, status: user.subscription_status });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// -----------------------------------------
// ROUTE: Get Policies (Example of Isolated Data)
// -----------------------------------------
app.get('/api/policies', authenticateJWT, async (req, res) => {
    try {
        // The company_id comes securely from the JWT, NOT the frontend request
        // This makes it impossible to query another company's data
        const [policies] = await db.execute(
            'SELECT * FROM policies WHERE company_id = ?', 
            [req.user.company_id]
        );
        res.json(policies);
    } catch (err) {
        res.status(500).json({ error: "Database error" });
    }
});

// Load the SMS and PayFast modules
require('./sms')(app, db, authenticateJWT);
require('./payfast')(app, db);


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SaaS Backend running on port ${PORT}`));