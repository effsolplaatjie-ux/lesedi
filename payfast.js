const crypto = require('crypto');

// Helper to verify PayFast's MD5 Signature
const generateSignature = (data, passPhrase = null) => {
    let pfOutput = "";
    for (let key in data) {
        if(data.hasOwnProperty(key)){
            if (data[key] !== "") {
                pfOutput +=`${key}=${encodeURIComponent(data[key].trim()).replace(/%20/g, "+")}&`
            }
        }
    }
    let getString = pfOutput.slice(0, -1);
    if (passPhrase !== null) {
        getString += `&passphrase=${encodeURIComponent(passPhrase.trim()).replace(/%20/g, "+")}`;
    }
    return crypto.createHash("md5").update(getString).digest("hex");
};

module.exports = function(app, db) {
    
    // -----------------------------------------
    // PayFast ITN Webhook Listener
    // -----------------------------------------
    app.post('/api/payfast/itn', async (req, res) => {
        // PayFast sends the data in the request body
        const pfData = req.body;
        const signature = pfData.signature;
        
        // Remove signature from object to verify
        delete pfData.signature;
        
        // TODO: In production, add your PayFast Passphrase here if you set one up
        const validSignature = generateSignature(pfData, process.env.PAYFAST_PASSPHRASE || null);

        if (signature !== validSignature) {
            console.error("PayFast Signature Mismatch");
            return res.status(400).send("Bad Signature");
        }

        // m_payment_id is the Company ID we pass to PayFast when they click "Pay"
        const company_id = pfData.m_payment_id;
        const payment_status = pfData.payment_status;

        try {
            if (payment_status === "COMPLETE") {
                // Payment Successful! Unlock the account.
                await db.execute(
                    `UPDATE companies 
                     SET subscription_status = 'active', subscription_date = CURDATE() 
                     WHERE id = ?`,
                    [company_id]
                );
                console.log(`Company ${company_id} payment complete. Account active.`);
            
            } else if (payment_status === "FAILED" || payment_status === "CANCELLED") {
                // Subscription failed or was cancelled.
                // Rule: If they paid before (subscription_date is not null), give read-only. 
                // If they never paid, lock them out.
                const [companyInfo] = await db.execute('SELECT subscription_date FROM companies WHERE id = ?', [company_id]);
                
                if (companyInfo.length > 0) {
                    const newStatus = companyInfo[0].subscription_date ? 'unpaid_readonly' : 'unpaid_lockout';
                    
                    await db.execute(
                        `UPDATE companies SET subscription_status = ? WHERE id = ?`,
                        [newStatus, company_id]
                    );
                    console.log(`Company ${company_id} payment failed. Status changed to ${newStatus}.`);
                }
            }
            
            // PayFast requires a 200 OK response so they stop pinging the server
            res.status(200).send("OK");

        } catch (err) {
            console.error("Database error during ITN:", err);
            res.status(500).send("Server Error");
        }
    });
};