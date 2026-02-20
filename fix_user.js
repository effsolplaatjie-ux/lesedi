require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs'); // Or 'bcrypt', use what's in your package.json

async function fix() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT,
        ssl: { rejectUnauthorized: true }
    });

    try {
        const password = "Lesedi1234@";
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        console.log("Generated Hash:", hash);

        // Clean up
        await db.execute('DELETE FROM users WHERE username = "Lesedi"');
        await db.execute('DELETE FROM companies WHERE id = 1');

        // Insert
        await db.execute(
            'INSERT INTO companies (id, name, subscription_status) VALUES (1, "Lesedi Life", "active")'
        );
        await db.execute(
            'INSERT INTO users (company_id, username, password_hash, role) VALUES (1, "Lesedi", ?, "admin")',
            [hash]
        );

        console.log("SUCCESS: User 'Lesedi' created with password 'Lesedi1234@'");
    } catch (err) {
        console.error("ERROR:", err);
    } finally {
        await db.end();
    }
}

fix();