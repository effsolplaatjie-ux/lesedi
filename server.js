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

const formatPhone = (phone) => {
    if (!phone) return '';
    let cleaned = phone.toString().replace(/\s+/g, '');
    if (cleaned.startsWith('0')) return '+27' + cleaned.substring(1);
    if (cleaned.startsWith('27')) return '+' + cleaned;
    if (!cleaned.startsWith('+')) return '+27' + cleaned;
    return cleaned;
};

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

// --- FILE UPLOAD CONFIG ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, '/tmp/'), 
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// --- ROUTES ---

// 0. REGISTER (Missing from original)
app.post('/api/register', async (req, res) => {
    const { companyName, username, password, whatsapp } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const [compResult] = await db.execute(
            'INSERT INTO companies (name, whatsapp) VALUES (?, ?)', 
            [companyName, whatsapp]
        );
        const companyId = compResult.insertId;

        await db.execute(
            'INSERT INTO users (username, password_hash, role, company_id) VALUES (?, ?, ?, ?)',
            [username, hash, 'admin', companyId]
        );
        res.status(201).json({ message: "Registration successful!", company_id: companyId });
    } catch (err) {
        res.status(500).json({ error: "Registration failed: " + err.message });
    }
});

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

// 2. EMPLOYEES
app.post('/api/employees/add', authenticateToken, async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO users (username, password_hash, role, company_id) VALUES (?, ?, ?, ?)',
            [username, hash, role || 'staff', req.user.company_id]
        );
        res.status(201).json({ message: "Employee added successfully!" });
    } catch (err) {
        res.status(500).json({ error: "Failed to add employee: " + err.message });
    }
});

app.get('/api/employees', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT id, username, role FROM users WHERE company_id = ?', [req.user.company_id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: "Fetch failed" });
    }
});

// 3. POLICIES
app.post('/api/policies/create', authenticateToken, async (req, res) => {
    const { type, hName, hID, hContact, hAddress, bName, bID, bContact, bAddress } = req.body;
    const policyNo = 'POL-' + Date.now().toString().slice(-6);
    try {
        await db.execute(
            `INSERT INTO policies (company_id, policy_no, policy_type, holder_name, holder_id_number, holder_contact, holder_address, beneficiary_name, beneficiary_id_number, beneficiary_contact, beneficiary_address) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.user.company_id, policyNo, type, hName, hID, hContact, hAddress, bName, bID, bContact || '', bAddress || '']
        );
        res.status(201).json({ message: "Policy saved successfully", policy_no: policyNo });
    } catch (err) {
        res.status(500).json({ error: "Database error: " + err.message });
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


// --- NEW: BILLING STATUS ROUTE ---
app.get('/api/billing/status', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT subscription_status, last_payment_date FROM companies WHERE id = ?', 
            [req.user.company_id]
        );
        if (rows.length === 0) return res.status(404).json({ error: "Company not found" });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Database error: " + err.message });
    }
});

// --- NEW: FETCH ALL CLAIMS FOR DASHBOARD ---
app.get('/api/claims', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT * FROM claims WHERE policy_no IN (SELECT policy_no FROM policies WHERE company_id = ?)', 
            [req.user.company_id]
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch claims: " + err.message });
    }
});

// 4. CLAIMS UPLOAD
app.post('/api/claims/upload', authenticateToken, upload.single('claimDoc'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file selected." });
        
        const { policy_no } = req.body;
        if (!policy_no) return res.status(400).json({ error: "Policy number is missing." });

        await db.execute(
            'INSERT INTO claims (policy_no, file_path) VALUES (?, ?)',
            [policy_no, req.file.path]
        );

        res.json({ message: "Claim submitted successfully!", filePath: req.file.path });
    } catch (err) {
        res.status(500).json({ error: "Upload failed: " + err.message });
    }
});

// 5. SMS
app.post('/api/sms/welcome', authenticateToken, async (req, res) => {
    const { hContact, hName } = req.body;
    try {
        await client.messages.create({
            body: `Welcome to Lesedi Life, ${hName}! Your policy is active.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: formatPhone(hContact)
        });
        res.json({ message: "Welcome SMS sent!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/sms/reminder', authenticateToken, async (req, res) => {
    const { policy_id, contact, name, policy } = req.body;
    try {
        let targetPhone = contact;
        let targetName = name;
        let targetPolicy = policy;

        // If frontend sends an ID instead of full details, look it up
        if (policy_id) {
            const [rows] = await db.execute('SELECT holder_name, holder_contact, policy_no FROM policies WHERE id = ?', [policy_id]);
            if (rows.length === 0) return res.status(404).json({ error: "Policy not found" });
            targetPhone = rows[0].holder_contact;
            targetName = rows[0].holder_name;
            targetPolicy = rows[0].policy_no;
        }

        await client.messages.create({
            body: `Hi ${targetName}, reminder to keep your Lesedi Life policy (${targetPolicy}) up to date.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: formatPhone(targetPhone)
        });
        res.json({ message: "Reminder sent!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update Policy Payment Status
app.put('/api/policies/status', authenticateToken, async (req, res) => {
    const { id, status } = req.body;
    try {
        await db.execute(
            'UPDATE policies SET payment_status = ? WHERE id = ? AND company_id = ?',
            [status, id, req.user.company_id]
        );
        res.json({ message: "Status updated successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));