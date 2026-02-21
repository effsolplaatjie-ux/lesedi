require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const twilio = require('twilio');

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

// --- TWILIO CONFIG ---
const client = new twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// Helper to ensure numbers are in +27 format for Twilio
const formatPhone = (phone) => {
    let cleaned = phone.replace(/\s+/g, '');
    if (cleaned.startsWith('0')) return '+27' + cleaned.substring(1);
    if (cleaned.startsWith('27')) return '+' + cleaned;
    if (!cleaned.startsWith('+')) return '+27' + cleaned;
    return cleaned;
};

// --- AUTHENTICATION MIDDLEWARE ---
// Moved up so it is defined before routes use it
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

// --- FILE UPLOAD CONFIG ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, '/tmp/'), // Use /tmp/ for Render's ephemeral disk
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

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

// 3. WELCOME SMS (Called after policy creation)
app.post('/api/sms/welcome', authenticateToken, async (req, res) => {
    const { hContact, hName } = req.body;
    try {
        await client.messages.create({
            body: `Welcome to Lesedi Life, ${hName}! Your policy has been successfully activated. Thank you for choosing us.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: formatPhone(hContact)
        });
        res.json({ message: "Welcome SMS sent!" });
    } catch (err) {
        res.status(500).json({ error: "SMS failed: " + err.message });
    }
});

// 4. SMS REMINDER
app.post('/api/sms/reminder', authenticateToken, async (req, res) => {
    const { policy_id } = req.body;
    try {
        const [rows] = await db.execute('SELECT holder_name, holder_contact, policy_no FROM policies WHERE id = ?', [policy_id]);
        if (rows.length === 0) return res.status(404).json({ error: "Policy not found" });
        const p = rows[0];
        
        await client.messages.create({
            body: `Hi ${p.holder_name}, this is a reminder to keep your Lesedi Life policy (${p.policy_no}) up to date.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: formatPhone(p.holder_contact)
        });
        res.json({ message: "Reminder SMS sent!" });
    } catch (err) {
        res.status(500).json({ error: "SMS failed: " + err.message });
    }
});

// 5. CLAIMS UPLOAD
app.post('/api/claims/upload', authenticateToken, upload.single('claimDoc'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });
        res.json({ message: "Document uploaded successfully!", filePath: req.file.path });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. GET POLICIES
app.get('/api/policies', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM policies WHERE company_id = ?', [req.user.company_id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));