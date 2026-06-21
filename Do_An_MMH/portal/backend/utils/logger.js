const fs = require('fs');
const path = require('path');
const db = require('../models/database');

function saveRegistry(REGISTRY_FILE) {
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(db.signatureRegistry, null, 2));
}

function logAudit(userId, action, details) {
    const logEntry = `[${new Date().toLocaleString()}] User: ${userId} | Action: ${action} | Info: ${details}\n`;
    fs.appendFileSync(path.join(__dirname, '../../storage/audit.log'), logEntry);
    console.log(`[AUDIT] ${action} - User: ${userId}`);
}

function revokeOldSignatures(fileHash, signType) {
    for (const key in db.signatureRegistry) {
        if (db.signatureRegistry[key].fileHash === fileHash) {
            db.signatureRegistry[key].revoked = true;
            logAudit("SYSTEM", "REVOKE_OLD_SIG", `Revoked old ${signType} signature for file hash ${fileHash}`);
        }
    }
}
module.exports = { saveRegistry, logAudit, revokeOldSignatures };
