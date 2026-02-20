const twilio = require('twilio');
const cron = require('node-cron');

// Initialize Twilio using your secure .env variables
const twilioClient = twilio(
    process.env.TWILIO_ACCOUNT_SID, 
    process.env.TWILIO_AUTH_TOKEN
);
const TWILIO_PHONE = process.env.TWILIO_PHONE_NUMBER;

module.exports = function(app, db, authenticateJWT) {
    
    // -----------------------------------------
    // 1. Manual Payment Reminder (Triggered by Admin/Employee)
    // -----------------------------------------
    app.post('/api/sms/reminder', authenticateJWT, async (req, res) => {
        const { policy_id } = req.body;
        const company_id = req.user.company_id;

        try {
            // Fetch policy ensuring it belongs to THIS company
            const [policies] = await db.execute(
                'SELECT holder_name, holder_contact FROM policies WHERE id = ? AND company_id = ?',
                [policy_id, company_id]
            );

            if (policies.length === 0) return res.status(404).json({ error: "Policy not found." });
            
            const client = policies[0];
            const message = `Dear ${client.holder_name}, this is a reminder that your policy payment is due. Please ensure payment to keep your cover active.`;

            // Send SMS via Twilio
            await twilioClient.messages.create({
                body: message,
                from: TWILIO_PHONE,
                to: client.holder_contact // Must be in E.164 format (e.g., +27821234567)
            });

            res.json({ success: true, message: "Reminder SMS sent." });
        } catch (err) {
            console.error("SMS Error:", err);
            res.status(500).json({ error: "Failed to send SMS." });
        }
    });

    // -----------------------------------------
    // 2. Automated Birthday SMS (Runs Daily at 8:00 AM)
    // -----------------------------------------
    cron.schedule('0 8 * * *', async () => {
        console.log("Running Daily Birthday Check...");
        try {
            // Find all active policies where the birthday matches today's month and day
            const [birthdays] = await db.execute(`
                SELECT p.holder_name, p.holder_contact, c.name as company_name 
                FROM policies p
                JOIN companies c ON p.company_id = c.id
                WHERE p.status = 'active' 
                AND MONTH(p.holder_dob) = MONTH(CURDATE()) 
                AND DAY(p.holder_dob) = DAY(CURDATE())
            `);

            for (let person of birthdays) {
                const message = `Happy Birthday ${person.holder_name}! Wishing you a wonderful day from the team at ${person.company_name}.`;
                
                await twilioClient.messages.create({
                    body: message,
                    from: TWILIO_PHONE,
                    to: person.holder_contact
                });
                console.log(`Birthday SMS sent to ${person.holder_name}`);
            }
        } catch (err) {
            console.error("Cron Job Error:", err);
        }
    });
};