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

const multer = require('multer');
const path = require('path');

// Configure where to save uploaded claim docs
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'), 
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// THE CLAIMS UPLOAD ROUTE
app.post('/api/claims/upload', authenticateToken, upload.single('claimDoc'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });

        // Save the file path to your database (Make sure you have a claims table!)
        // await db.execute('INSERT INTO claims (policy_id, file_path) VALUES (?, ?)', [req.body.policy_id, req.file.path]);

        res.json({ message: "Document uploaded successfully!", filePath: req.file.path });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
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

// 2. CREATE POLICY
app.post('/api/policies/create', authenticateToken, async (req, res) => {
    const { type, hName, hID, hContact, hAddress, bName, bID, bContact, bAddress } = req.body;
    const companyId = req.user.company_id;
    const policyNo = 'POL-' + Date.now().toString().slice(-6);
    try {
        await db.execute(
            `INSERT INTO policies (company_id, policy_no, policy_type, holder_name, holder_id_number, holder_contact, holder_address, beneficiary_name, beneficiary_id_number, beneficiary_contact, beneficiary_address) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, policyNo, type, hName, hID, hContact, hAddress, bName, bID, bContact, bAddress]
        );
        res.status(201).json({ message: "Policy saved successfully", policy_no: policyNo });
    } catch (err) {
        res.status(500).json({ error: "Database error: " + err.message });
    }
});

const twilio = require('twilio');
// Add these variables to your .env file on Render
const client = new twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

app.post('/api/sms/reminder', authenticateToken, async (req, res) => {
    const { policy_id } = req.body;
    try {
        const [rows] = await db.execute('SELECT holder_name, holder_contact, policy_no FROM policies WHERE id = ?', [policy_id]);
        const p = rows[0];
        
        // ACTUAL SENDING LOGIC
        await client.messages.create({
            body: `Hi ${p.holder_name}, this is a reminder to keep your Lesedi Life policy (${p.policy_no}) up to date.`,
            from: process.env.TWILIO_PHONE_NUMBER, // Your Twilio number
            to: p.holder_contact // Ensure this is in international format (e.g., +27...)
        });

        res.json({ message: "SMS actually sent to phone!" });
    } catch (err) {
        console.error("Twilio Error:", err);
        res.status(500).json({ error: "SMS Gateway failed: " + err.message });
    }
});

app.get('/api/policies', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM policies WHERE company_id = ?', [req.user.company_id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/company-info', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT id, name, whatsapp_number FROM companies WHERE id = ?', [req.user.company_id]);
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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