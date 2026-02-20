require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// --- DATABASE CONNECTION ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000,
    ssl: { rejectUnauthorized: true }
});

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access Denied" });

    try {
        const decoded = jwt.decode(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: "Invalid Token" });
    }
};

// --- ROUTES ---

// 1. LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(404).json({ error: "User not found" });

        const user = rows[0];
        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) return res.status(401).json({ error: "Invalid password" });

        const token = jwt.encode({ id: user.id, company_id: user.company_id, role: user.role }, process.env.JWT_SECRET);
        res.json({ token, role: user.role, company_id: user.company_id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. CREATE POLICY (BACKEND STORAGE)
app.post('/api/policies/create', authenticateToken, async (req, res) => {
    const { type, hName, hID, hContact, hAddress, bName, bID } = req.body;
    const companyId = req.user.company_id;
    const policyNo = 'POL-' + Date.now().toString().slice(-6);

    try {
        await db.execute(
            `INSERT INTO policies (company_id, policy_no, policy_type, holder_name, holder_id_number, holder_contact, holder_address, beneficiary_name, beneficiary_id_number) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, policyNo, type, hName, hID, hContact, hAddress, bName, bID]
        );
        res.status(201).json({ message: "Policy saved successfully", policy_no: policyNo });
    } catch (err) {
        res.status(500).json({ error: "Database error: " + err.message });
    }
});

// 3. GET POLICIES
app.get('/api/policies', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM policies WHERE company_id = ?', [req.user.company_id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. GET COMPANY INFO (FOR PUBLIC PORTAL LINK)
app.get('/api/company-info', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT id, name, whatsapp_number FROM companies WHERE id = ?', [req.user.company_id]);
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. PUBLIC CREATE (FOR SELF-SERVICE PORTAL)
app.post('/api/policies/public-create', async (req, res) => {
    const { company_id, hName, hID, hContact, hAddress, bName, bID } = req.body;
    const policyNo = 'PUB-' + Date.now().toString().slice(-6);

    try {
        await db.execute(
            `INSERT INTO policies (company_id, policy_no, policy_type, holder_name, holder_id_number, holder_contact, holder_address, beneficiary_name, beneficiary_id_number) 
             VALUES (?, ?, 'Self-Service', ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNo, hName, hID, hContact, hAddress, bName, bID]
        );
        res.status(201).json({ message: "Application submitted" });
    } catch (err) {
        res.status(500).json({ error: "Submission failed" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));