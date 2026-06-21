const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const { execSync } = require('child_process');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const { checkOCSP } = require('../../verifier/ocspVerifier');
const QRCode = require('qrcode');
const sqlite3 = require('sqlite3').verbose();

let jose;
async function getJose() {
    if (!jose) {
        jose = await import('jose');
    }
    return jose;
}

let graphene;
try {
    graphene = require("graphene-pk11");
} catch (e) {
    console.warn("⚠️ Cảnh báo: Không thể nạp thư viện graphene-pk11. Tính năng CloudHSM sẽ bị vô hiệu hóa.");
}
const Module = graphene ? graphene.Module : null;

const app = express();
app.enable('trust proxy');
const port = 3000;

// Thiết lập môi trường cho SoftHSM2
const hsmConfigPath = path.join(__dirname, '../../ca-infrastructure/storage/softhsm2/softhsm2.conf');
process.env.SOFTHSM2_CONF = hsmConfigPath;

function getPythonCommand() {
    // 1. Kiểm tra môi trường ảo venv trong portal/backend
    const venvPythonLinux = path.join(__dirname, 'venv/bin/python');
    const venvPythonWindows = path.join(__dirname, 'venv/Scripts/python.exe');
    
    if (fs.existsSync(venvPythonLinux)) {
        return `"${venvPythonLinux}"`;
    }
    if (fs.existsSync(venvPythonWindows)) {
        return `"${venvPythonWindows}"`;
    }
    
    // 2. Kiểm tra venv ở thư mục cha (nếu có)
    const parentVenvLinux = path.join(__dirname, '../../venv/bin/python');
    const parentVenvWindows = path.join(__dirname, '../../venv/Scripts/python.exe');
    if (fs.existsSync(parentVenvLinux)) {
        return `"${parentVenvLinux}"`;
    }
    if (fs.existsSync(parentVenvWindows)) {
        return `"${parentVenvWindows}"`;
    }

    // 3. Dự phòng theo hệ điều hành
    return process.platform === 'win32' ? 'python' : 'python3';
}

// Tự động khởi tạo HSM nếu chưa có
if (!fs.existsSync(hsmConfigPath)) {
    try {
        const setupScript = path.join(__dirname, '../../ca-infrastructure/setup-hsm.sh');
        if (fs.existsSync(setupScript)) {
            console.log("🚀 Đang thử khởi tạo hệ thống HSM...");
            execSync(`bash "${setupScript}"`, { stdio: 'inherit', cwd: path.join(__dirname, '..') });
        } else {
            console.warn("⚠️ Không tìm thấy file setup-hsm.sh, bỏ qua bước khởi tạo HSM.");
        }
    } catch (e) {
        console.warn("⚠️ Cảnh báo: Chưa thể khởi tạo HSM (Có thể thiếu thư viện). Hệ thống vẫn hoạt động ở chế độ Fallback.");
    }
}

app.use(cors());
app.use(express.json());

// Middleware log toàn cục để debug kết nối
app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.url}`);
    next();
});

// ==========================================
// 1. KHỞI TẠO CẤU TRÚC THƯ MỤC & DATABASE
// ==========================================
const KEYSTORE_DIR = path.join(__dirname, '../../ca-infrastructure/storage/keystore');
const CA_DIR = path.join(__dirname, '../../ca-infrastructure/storage/ca-authority');
const SIGNED_DIR = path.join(__dirname, '../../ca-infrastructure/storage/signed_documents');
const HISTORY_DIR = path.join(KEYSTORE_DIR, 'history');
const REMOTE_KEYS_DIR = path.join(KEYSTORE_DIR, 'remote_keys');
const LTV_ARCHIVE_DIR = path.join(__dirname, '../../verifier/ltv_archive');
const CRL_FILE = path.join(KEYSTORE_DIR, 'crl.json');
const DB_FILE = path.join(__dirname, 'database.sqlite');

[KEYSTORE_DIR, CA_DIR, SIGNED_DIR, HISTORY_DIR, REMOTE_KEYS_DIR, LTV_ARCHIVE_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

if (!fs.existsSync(CRL_FILE)) fs.writeFileSync(CRL_FILE, JSON.stringify([]));

const upload = multer({ storage: multer.memoryStorage() });

// Thiết lập kết nối SQLite
const db = new sqlite3.Database(DB_FILE);

const dbRun = (query, params = []) => new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
        if (err) reject(err);
        else resolve(this);
    });
});

const dbGet = (query, params = []) => new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
    });
});

const dbAll = (query, params = []) => new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
    });
});

async function initDatabase() {
    await dbRun(`
        CREATE TABLE IF NOT EXISTS users (
            userId TEXT PRIMARY KEY,
            role TEXT,
            name TEXT,
            password TEXT,
            hasCert INTEGER DEFAULT 0,
            p12Path TEXT,
            hasRemoteCert INTEGER DEFAULT 0,
            signPin TEXT,
            remoteKeyPath TEXT,
            remoteCrtPath TEXT,
            certPin TEXT,
            hoTen TEXT,
            cccd TEXT,
            ngaySinh TEXT,
            gioiTinh TEXT,
            noiThuongTru TEXT,
            email TEXT,
            phone TEXT
        )
    `);

    await dbRun(`
        CREATE TABLE IF NOT EXISTS pdf_cache (
            fileId TEXT PRIMARY KEY,
            buffer BLOB,
            name TEXT,
            hash TEXT,
            ownerId TEXT,
            status TEXT,
            hoTen TEXT,
            cccd TEXT,
            noiThuongTru TEXT,
            ngayGui TEXT,
            downloadUrl TEXT,
            downloadUrlSig TEXT,
            approvedBy TEXT,
            approvedAt TEXT,
            rejectedBy TEXT,
            rejectReason TEXT,
            rejectedAt TEXT,
            signedBy TEXT,
            signType TEXT,
            mucDich TEXT,
            email TEXT,
            phone TEXT,
            ghiChu TEXT
        )
    `);

    await dbRun(`
        CREATE TABLE IF NOT EXISTS signature_registry (
            fileId TEXT PRIMARY KEY,
            signatureId TEXT,
            userId TEXT,
            timestamp TEXT,
            signature TEXT,
            fileHash TEXT,
            revoked INTEGER DEFAULT 0,
            type TEXT,
            certificatePEM TEXT,
            signerCertPath TEXT
        )
    `);

    const count = await dbGet("SELECT COUNT(*) as count FROM users");
    if (count.count === 0) {
        const defaultUsers = [
            ["officer_01", "OFFICER", "Can Bo Cong An Phuong", "456", 0, "", 0, "", "", "", "", "Can Bo Cong An Phuong", "", "", "", "", "", ""],
            ["0522 0100 7777", "Citizen", "Nguyễn Văn A", "123456", 0, "", 0, "", "", "", "", "Nguyễn Văn A", "0522 0100 7777", "2003-04-15", "Nam", "123k Lê Lợi, Phường Linh Trung, TP. Thủ Đức", "nguyenvana@example.com", "0901234567"],
            ["0522 0100 8888", "Citizen", "Trần Thị B", "123456", 0, "", 0, "", "", "", "", "Trần Thị B", "0522 0100 8888", "2003-09-20", "Nu", "456 Nguyễn Huệ, Phường Linh Chiểu, TP. Thủ Đức", "tranthib@example.com", "0912345678"]
        ];

        for (const u of defaultUsers) {
            await dbRun(`
                INSERT INTO users (
                    userId, role, name, password, hasCert, p12Path, hasRemoteCert, 
                    signPin, remoteKeyPath, remoteCrtPath, certPin, hoTen, cccd, 
                    ngaySinh, gioiTinh, noiThuongTru, email, phone
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, u);
        }
        console.log("Seeded default users to SQLite database.");
    }
}

// Khởi chạy đồng bộ hóa DB khi start
initDatabase().catch(err => console.error("Lỗi khởi tạo DB:", err));

async function getUser(userId) {
    const u = await dbGet("SELECT * FROM users WHERE userId = ?", [userId]);
    if (u) {
        u.hasCert = !!u.hasCert;
        u.hasRemoteCert = !!u.hasRemoteCert;
    }
    return u;
}

async function updateUser(userId, fields) {
    const keys = Object.keys(fields);
    const values = Object.values(fields);
    const setClause = keys.map(k => `${k} = ?`).join(', ');
    await dbRun(`UPDATE users SET ${setClause} WHERE userId = ?`, [...values, userId]);
}

async function getCachedFile(fileId) {
    const row = await dbGet("SELECT * FROM pdf_cache WHERE fileId = ?", [fileId]);
    return row;
}

async function saveCachedFile(fileId, fileData) {
    const existing = await getCachedFile(fileId);
    const keys = Object.keys(fileData);
    const values = Object.values(fileData);
    
    if (existing) {
        const setClause = keys.map(k => `${k} = ?`).join(', ');
        await dbRun(`UPDATE pdf_cache SET ${setClause} WHERE fileId = ?`, [...values, fileId]);
    } else {
        const columns = ['fileId', ...keys].join(', ');
        const placeholders = ['?', ...keys.map(() => '?')].join(', ');
        await dbRun(`INSERT INTO pdf_cache (${columns}) VALUES (${placeholders})`, [fileId, ...values]);
    }
}

async function getSignature(fileId) {
    const row = await dbGet("SELECT * FROM signature_registry WHERE fileId = ?", [fileId]);
    if (row) {
        row.revoked = row.revoked === 1;
    }
    return row;
}

async function saveSignature(fileId, sigData) {
    const existing = await getSignature(fileId);
    const fields = {
        signatureId: sigData.signatureId,
        userId: sigData.userId,
        timestamp: sigData.timestamp,
        signature: sigData.signature,
        fileHash: sigData.fileHash,
        revoked: sigData.revoked ? 1 : 0,
        type: sigData.type,
        certificatePEM: sigData.certificatePEM || null,
        signerCertPath: sigData.signerCertPath || null
    };
    
    if (existing) {
        const keys = Object.keys(fields);
        const values = Object.values(fields);
        const setClause = keys.map(k => `${k} = ?`).join(', ');
        await dbRun(`UPDATE signature_registry SET ${setClause} WHERE fileId = ?`, [...values, fileId]);
    } else {
        const keys = Object.keys(fields);
        const values = Object.values(fields);
        const columns = ['fileId', ...keys].join(', ');
        const placeholders = ['?', ...keys.map(() => '?')].join(', ');
        await dbRun(`INSERT INTO signature_registry (${columns}) VALUES (${placeholders})`, [fileId, ...values]);
    }
}

async function revokeOldSignatures(fileHash, signType) {
    await dbRun("UPDATE signature_registry SET revoked = 1 WHERE fileHash = ? AND type = ?", [fileHash, signType]);
    logAudit("SYSTEM", "REVOKE_OLD_SIG", `Revoked old ${signType} signature for file hash ${fileHash}`);
}

function nowVN() {
    return new Date().toLocaleString('vi-VN', {
        timeZone: 'Asia/Ho_Chi_Minh',
        hour12: false
    });
}

function formatDateVN(dateStr) {
    if (!dateStr) return "";
    const [y, m, d] = dateStr.split("-");
    return `${d}/${m}/${y}`;
}

let globalSignedHistory = [];
let nonceCache = new Set();
let dpopJtiCache = new Map();

function cleanupDpopJtiCache() {
    const now = Date.now();
    for (const [jti, expiresAt] of dpopJtiCache.entries()) {
        if (expiresAt <= now) {
            dpopJtiCache.delete(jti);
        }
    }
}
setInterval(cleanupDpopJtiCache, 60 * 1000);

function logAudit(userId, action, details) {
    const logEntry = `[${nowVN()}] User: ${userId} | Action: ${action} | Info: ${details}\n`;
    fs.appendFileSync(path.join(__dirname, 'audit.log'), logEntry);
    console.log(`[AUDIT] ${action} - User: ${userId}`);
}

async function callOPA(input) {
    try {
        const opaUrl = process.env.OPA_URL || "http://localhost:8181";
        const response = await fetch(`${opaUrl}/v1/data/nt219/authz/allow`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ input })
        });
        const data = await response.json();
        if (data.result === undefined) {
            return { allowed: false, error: "Policy path nt219/authz/allow not found in OPA" };
        }
        return { allowed: data.result === true, error: null };
    } catch (e) {
        console.error("[OPA] Error:", e.message);
        return { allowed: false, error: `Connection failed: ${e.message}` };
    }
}

function getRequestUrlForDpop(req) {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const pathOnly = req.originalUrl.split('?')[0];
    return `${protocol}://${host}${pathOnly}`;
}

async function requireDPoP(req, res, next) {
    try {
        const dpopProof = req.headers['dpop'];
        if (!dpopProof) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", "Missing DPoP proof");
            return res.status(401).json({ status: "FAILED", message: "DPoP proof is required." });
        }

        const parts = dpopProof.split('.');
        if (parts.length !== 3) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", "Invalid DPoP JWT format");
            return res.status(401).json({ status: "FAILED", message: "Invalid DPoP proof format." });
        }

        const headerJson = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        if (headerJson.typ !== "dpop+jwt") {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", "Invalid DPoP typ");
            return res.status(401).json({ status: "FAILED", message: "Invalid DPoP typ." });
        }

        if (!headerJson.jwk) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", "Missing DPoP public JWK");
            return res.status(401).json({ status: "FAILED", message: "Missing DPoP public JWK." });
        }

        const { jwtVerify, importJWK, calculateJwkThumbprint } = await getJose();
        const publicKey = await importJWK(headerJson.jwk, headerJson.alg || "ES256");

        const { payload } = await jwtVerify(dpopProof, publicKey, { typ: "dpop+jwt" });
        const expectedHtm = req.method.toUpperCase();
        const expectedHtu = getRequestUrlForDpop(req);

        if (payload.htm !== expectedHtm) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", `Invalid htm: expected=${expectedHtm}, got=${payload.htm}`);
            return res.status(401).json({ status: "FAILED", message: "Invalid DPoP htm." });
        }

        if (payload.htu !== expectedHtu) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", `Invalid htu: expected=${expectedHtu}, got=${payload.htu}`);
            return res.status(401).json({ status: "FAILED", message: "Invalid DPoP htu." });
        }

        const now = Math.floor(Date.now() / 1000);
        const maxAgeSeconds = 120;

        if (!payload.iat || Math.abs(now - payload.iat) > maxAgeSeconds) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", "DPoP proof expired or invalid iat");
            return res.status(401).json({ status: "FAILED", message: "DPoP proof expired." });
        }

        if (!payload.jti) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", "Missing DPoP jti");
            return res.status(401).json({ status: "FAILED", message: "Missing DPoP jti." });
        }

        if (dpopJtiCache.has(payload.jti)) {
            logAudit(req.body?.officerId || req.body?.userId || "Unknown", "REPLAY_ATTACK_BLOCKED", `Reused DPoP jti: ${payload.jti}`);
            return res.status(401).json({ status: "FAILED", message: "Replay Attack Blocked: DPoP jti was already used." });
        }

        dpopJtiCache.set(payload.jti, Date.now() + maxAgeSeconds * 1000);

        req.dpop = {
            jti: payload.jti,
            jwkThumbprint: await calculateJwkThumbprint(headerJson.jwk)
        };

        logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_ALLOW", `DPoP verified jti=${payload.jti}`);
        next();
    } catch (e) {
        console.error("[DPOP] Error:", e.message);
        logAudit(req.body?.officerId || req.body?.userId || "Unknown", "DPOP_DENY", e.message);
        return res.status(401).json({ status: "FAILED", message: "Invalid DPoP proof." });
    }
}

function saveLTVArchive(evidence) {
    try {
        const safeTime = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `verify_${safeTime}.json`;
        const archivePath = path.join(LTV_ARCHIVE_DIR, fileName);
        fs.writeFileSync(archivePath, JSON.stringify(evidence, null, 2));
        console.log(`[LTV] Archived verification evidence: ${fileName}`);
    } catch (e) {
        console.warn("[LTV] Archive failed:", e.message);
    }
}

function checkTrustChain(certPath) {
    try {
        if (!certPath || !fs.existsSync(certPath)) {
            return { valid: false, message: "Không tìm thấy chứng chỉ người ký" };
        }
        const rootCA = path.join(CA_DIR, 'rootCA.pem');
        const subCA = path.join(CA_DIR, 'subCA.pem');

        execSync(`openssl verify -CAfile "${rootCA}" -untrusted "${subCA}" "${certPath}"`, { stdio: 'pipe' });
        console.log("=== TRUST CHAIN RESULT: VALID ===");
        return { valid: true, message: "TRUST_CHAIN_VALID" };
    } catch (e) {
        console.log("=== TRUST CHAIN RESULT: INVALID ===");
        if (e.stdout) console.log(e.stdout.toString());
        return { valid: false, message: "TRUST_CHAIN_INVALID" };
    }
}

// ==========================================
// 3. MIDDLEWARE & HSM PKCS#11
// ==========================================
function gatewayPEPMiddleware(req, res, next) {
    const dpopNonce = req.headers['x-dpop-nonce'];
    if (!dpopNonce || !nonceCache.has(dpopNonce)) {
        logAudit(req.body.userId || 'Unknown', "REPLAY_ATTACK_BLOCKED", "Invalid or reused Nonce");
        return res.status(401).json({ status: "FAILED", message: "NGINX/PEP Blocked: Phát hiện Replay Attack hoặc Nonce không hợp lệ!" });
    }
    nonceCache.delete(dpopNonce);
    next();
}

async function opaPolicyMiddleware(req, res, next) {
    const { userId, fileId } = req.body;
    const user = await getUser(userId);
    const cachedFile = await getCachedFile(fileId);

    let decision = "DENY";
    let reason = "";

    if (!user || user.role !== "Citizen") {
        reason = "RBAC Failed: Người dùng không có Role Citizen";
    }
    else if (!cachedFile || cachedFile.ownerId !== userId) {
        reason = "Ownership Failed: Người dùng không phải chủ sở hữu tài liệu này";
    }
    else if (cachedFile.status !== "APPROVED") {
        reason = "Approval Required: Hồ sơ chưa được cán bộ phê duyệt!";
    }
    else {
        decision = "ALLOW";
    }

    logAudit(userId, `OPA_DECISION_${decision}`, reason || "Passed RBAC, Ownership & Approval");

    if (decision === "DENY") {
        return res.status(403).json({
            status: "FAILED",
            message: `OPA Blocked: ${reason}`
        });
    }
    next();
}

function getPublicKeyPEM() {
    try {
        const paths = [
            '/usr/lib/softhsm/libsofthsm2.so',
            '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
            '/usr/local/lib/softhsm/libsofthsm2.so'
        ];
        let libPath = paths.find(p => fs.existsSync(p));
        if (!libPath) throw new Error("Không có thư viện SoftHSM trong Docker/Linux");

        const module = graphene.Module.load(libPath, 'SoftHSM');
        module.initialize();
        const slots = module.getSlots(true);
        let slot = null;

        for (let i = 0; i < slots.length; i++) {
            try {
                if (slots.items(i).getToken().label.trim() === "CloudHSM") {
                    slot = slots.items(i); break;
                }
            } catch (e) { }
        }
        if (!slot) throw new Error("Không tìm thấy slot CloudHSM");

        const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
        try { session.login("123456"); } catch (e) { }

        let publicKey = session.find({ class: graphene.ObjectClass.PUBLIC_KEY, label: "mykey" }).items(0);
        if (!publicKey) publicKey = session.find({ class: graphene.ObjectClass.PUBLIC_KEY, id: Buffer.from([0x01]) }).items(0);
        if (!publicKey) throw new Error("Không tìm thấy public key trong HSM");

        const attrs = publicKey.getAttribute({ modulus: null, publicExponent: null });
        session.logout(); session.close(); module.finalize();

        if (!attrs.modulus || !attrs.publicExponent) throw new Error("Key trong HSM thiếu thuộc tính RSA");

        return crypto.createPublicKey({
            key: {
                kty: 'RSA',
                n: attrs.modulus.toString('base64url'),
                e: attrs.publicExponent.toString('base64url')
            },
            format: 'jwk'
        }).export({ format: 'pem', type: 'spki' });

    } catch (e) {
        console.log("❌ FALLBACK - LẤY PUBLIC KEY TỪ SUB CA PEM:", e.message);
        const subCaPemPath = path.join(CA_DIR, 'subCA.pem');
        if (fs.existsSync(subCaPemPath)) {
            const certPem = fs.readFileSync(subCaPemPath, 'utf8');
            return crypto.createPublicKey(certPem).export({ format: 'pem', type: 'spki' });
        }
        const privateKeyPem = fs.readFileSync(path.join(CA_DIR, 'subCA.key'), 'utf8');
        return crypto.createPublicKey(privateKeyPem).export({ format: 'pem', type: 'spki' });
    }
}

function hsmSignPKCS11(dataHashHex, pin = "123456") {
    const paths = [
        '/usr/lib/softhsm/libsofthsm2.so',
        '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
        '/usr/local/lib/softhsm/libsofthsm2.so'
    ];
    let libPath = paths.find(p => fs.existsSync(p));

    // Kiểm tra graphene-pk11 và SoftHSM có sẵn sàng không
    const GrapheneModule = graphene ? graphene.Module : null;

    if (!libPath || !GrapheneModule) {
        console.warn(`⚠️ Fallback soft-sign: HSM unavailable (libPath=${libPath}, graphene=${!!graphene})`);
        // Dùng khóa riêng của subCA để ký thay thế (software fallback)
        const subCAKeyPath = path.join(CA_DIR, 'subCA.key');
        if (!fs.existsSync(subCAKeyPath)) {
            throw new Error("Không tìm thấy khóa SubCA để ký dự phòng. Vui lòng chạy lại setup-hsm.sh trên máy chủ.");
        }
        const privateKeyPem = fs.readFileSync(subCAKeyPath, 'utf8');
        try {
            // Thử ký ECDSA trước (nếu subCA.key là EC key)
            const sign = crypto.createSign('SHA256');
            sign.update(Buffer.from(dataHashHex, 'hex'));
            return sign.sign(privateKeyPem, 'base64');
        } catch (e) {
            // Fallback RSA
            const sign = crypto.createSign('RSA-SHA256');
            sign.update(Buffer.from(dataHashHex, 'hex'));
            return sign.sign(privateKeyPem, 'base64');
        }
    }

    let mod, session;
    try {
        mod = GrapheneModule.load(libPath, "SoftHSM");
        mod.initialize();
        const slots = mod.getSlots(true);
        let slot = null;

        for (let i = 0; i < slots.length; i++) {
            const s = slots.items(i);
            try {
                if (s.getToken().label.trim() === "CloudHSM") { slot = s; break; }
            } catch (e) { }
        }

        if (!slot) throw new Error("Không tìm thấy slot CloudHSM trong SoftHSM. Hãy chạy lại setup-hsm.sh.");
        session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);

        try { session.login(pin); } catch (e) {
            if (!e.message.includes("CKR_USER_ALREADY_LOGGED_IN")) throw e;
        }

        let privateKey = session.find({ class: graphene.ObjectClass.PRIVATE_KEY, label: "mykey" }).items(0);
        if (!privateKey) privateKey = session.find({ class: graphene.ObjectClass.PRIVATE_KEY, id: Buffer.from([0x01]) }).items(0);
        if (!privateKey) throw new Error("Không tìm thấy private key trong slot CloudHSM");

        let signer;
        try {
            signer = session.createSign({ name: "ECDSA" }, privateKey);
        } catch (e) {
            const pssParams = new graphene.RsaPssParams(graphene.MechanismEnum.SHA256, graphene.RsaMgf.MGF1_SHA256, 32);
            signer = session.createSign({ name: "RSA_PKCS_PSS", params: pssParams }, privateKey);
        }

        const digest = Buffer.from(dataHashHex, 'hex');
        return signer.once(digest).toString("base64");
    } catch (err) {
        console.error("❌ HSM ERROR:", err.message); throw err;
    } finally {
        if (session) { try { session.logout(); } catch { } try { session.close(); } catch { } }
        if (mod) { try { mod.finalize(); } catch { } }
    }
}

// ==========================================
// 4. QUẢN LÝ CRL & CHỨNG CHỈ 
// ==========================================
function getRevokedList() {
    try {
        const data = fs.readFileSync(CRL_FILE, 'utf8');
        if (!data || data.trim() === "") return [];
        return JSON.parse(data);
    } catch (e) {
        return [];
    }
}

function addToCRL(userId, name) {
    const list = getRevokedList();
    if (!list.find(i => i.userId === userId)) {
        list.push({ userId, name, revokedAt: nowVN() });
        fs.writeFileSync(CRL_FILE, JSON.stringify(list));
        logAudit(userId, "CERT_REVOKED", `User ${name} added to CRL`);
    }
}

function formatOpenSSLDate(date) {
    const yy = String(date.getUTCFullYear()).slice(-2);
    const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(date.getUTCDate()).padStart(2, '0');
    const hh = String(date.getUTCHours()).padStart(2, '0');
    const mi = String(date.getUTCMinutes()).padStart(2, '0');
    const ss = String(date.getUTCSeconds()).padStart(2, '0');
    return `${yy}${mm}${dd}${hh}${mi}${ss}Z`;
}

function registerCertToOCSP(certPath) {
    try {
        const ocspIndex = path.join(__dirname, '../../ca-infrastructure/ocsp/index.txt');
        const serial = execSync(`openssl x509 -in "${certPath}" -noout -serial`).toString().trim().replace('serial=', '').toUpperCase();
        const subject = execSync(`openssl x509 -in "${certPath}" -noout -subject -nameopt compat`).toString().trim().replace(/^subject=\s*/, '');
        const endDateRaw = execSync(`openssl x509 -in "${certPath}" -noout -enddate`).toString().trim().replace('notAfter=', '');
        const expiry = formatOpenSSLDate(new Date(endDateRaw));

        let lines = [];
        if (fs.existsSync(ocspIndex)) {
            lines = fs.readFileSync(ocspIndex, 'utf8')
                .split(/\r?\n/)
                .filter(Boolean)
                .filter(line => {
                    const cols = line.split('\t');
                    if (cols[3] === serial) return false;
                    if (cols[5] === subject) return false;
                    return true;
                });
        }
        lines.push(`V\t${expiry}\t\t${serial}\tunknown\t${subject}`);
        fs.writeFileSync(ocspIndex, lines.join('\n') + '\n');
        console.log(`[OCSP] Registered cert ${serial}`);
    } catch (e) {
        console.warn("[OCSP] Register failed:", e.message);
    }
}

function revokeCertInOCSP(certPath) {
    try {
        const ocspIndex = path.join(__dirname, '../../ca-infrastructure/ocsp/index.txt');
        const serial = execSync(`openssl x509 -in "${certPath}" -noout -serial`).toString().trim().replace('serial=', '').toUpperCase();
        const subject = execSync(`openssl x509 -in "${certPath}" -noout -subject -nameopt compat`).toString().trim().replace(/^subject=\s*/, '');
        const endDateRaw = execSync(`openssl x509 -in "${certPath}" -noout -enddate`).toString().trim().replace('notAfter=', '');
        const expiry = formatOpenSSLDate(new Date(endDateRaw));
        const revokeTime = formatOpenSSLDate(new Date());

        let found = false;
        let lines = [];
        if (fs.existsSync(ocspIndex)) {
            lines = fs.readFileSync(ocspIndex, 'utf8')
                .split(/\r?\n/)
                .filter(Boolean)
                .filter(line => {
                    const cols = line.split('\t');
                    if (cols[5] === subject && cols[3] !== serial) return false;
                    return true;
                })
                .map(line => {
                    const cols = line.split('\t');
                    if (cols[3] === serial) {
                        found = true;
                        return `R\t${cols[1] || expiry}\t${revokeTime}\t${serial}\tunknown\t${subject}`;
                    }
                    return line;
                });
        }
        if (!found) {
            lines.push(`R\t${expiry}\t${revokeTime}\t${serial}\tunknown\t${subject}`);
        }
        fs.writeFileSync(ocspIndex, lines.join('\n') + '\n');
        console.log(`[OCSP] Revoked cert ${serial}`);
    } catch (e) {
        console.warn("[OCSP] Revoke failed:", e.message);
    }
}

function generateCitizenCert(userId, userName, userPin) {
    const filename = `citizen_${userId}`;
    const p12Output = path.join(KEYSTORE_DIR, `${filename}.p12`);

    const list = getRevokedList().filter(i => i.userId !== userId);
    fs.writeFileSync(CRL_FILE, JSON.stringify(list));

    if (fs.existsSync(p12Output)) fs.renameSync(p12Output, path.join(HISTORY_DIR, `${filename}_${Date.now()}.p12`));

    const keyPath = path.join(KEYSTORE_DIR, `${filename}.key`);
    const csrPath = path.join(KEYSTORE_DIR, `${filename}.csr`);
    const crtPath = path.join(KEYSTORE_DIR, `${filename}.crt`);
    const caCrt = path.join(CA_DIR, 'subCA.pem');
    const rootCrt = path.join(CA_DIR, 'rootCA.pem');
    const caKey = path.join(CA_DIR, 'subCA.key');

    if (!fs.existsSync(caCrt)) return null;

    try {
        const serial = Date.now();
        const cmd = `openssl ecparam -name prime256v1 -genkey -noout -out "${keyPath}" && ` +
            `openssl req -new -key "${keyPath}" -out "${csrPath}" -subj "/C=VN/O=Citizen/CN=${userId}_${userName}" && ` +
            `openssl x509 -req -in "${csrPath}" -CA "${caCrt}" -CAkey "${caKey}" -set_serial ${serial} -out "${crtPath}" -days 365 -sha256 && ` +
            `openssl pkcs12 -export -legacy -out "${p12Output}" -inkey "${keyPath}" -in "${crtPath}" -certfile "${caCrt}" -certfile "${rootCrt}" -passout pass:${userPin}`;
        execSync(cmd, { stdio: 'pipe' });
        registerCertToOCSP(crtPath);
        [keyPath, csrPath].forEach(f => fs.existsSync(f) && fs.unlinkSync(f));
        logAudit(userId, "ISSUE_LOCAL_CERT", "Success");
        return p12Output;
    } catch (error) { return null; }
}

function generateRemoteCert(userId, userName, pin) {
    const filename = `remote_${userId}`;
    const keyPath = path.join(REMOTE_KEYS_DIR, `${filename}.key`);
    const csrPath = path.join(REMOTE_KEYS_DIR, `${filename}.csr`);
    const crtPath = path.join(REMOTE_KEYS_DIR, `${filename}.crt`);
    const caCrt = path.join(CA_DIR, 'subCA.pem');
    const caKey = path.join(CA_DIR, 'subCA.key');

    const list = getRevokedList().filter(i => i.userId !== userId);
    fs.writeFileSync(CRL_FILE, JSON.stringify(list));

    if (!fs.existsSync(caCrt)) return false;

    try {
        const serial = Date.now();
        const cmd = `openssl ecparam -name prime256v1 -genkey -noout -out "${keyPath}" && ` +
            `openssl req -new -key "${keyPath}" -out "${csrPath}" -subj "/C=VN/O=CloudCitizen/CN=${userId}_${userName}" && ` +
            `openssl x509 -req -in "${csrPath}" -CA "${caCrt}" -CAkey "${caKey}" -set_serial ${serial} -out "${crtPath}" -days 365 -sha256`;
        execSync(cmd, { stdio: 'pipe' });
        registerCertToOCSP(crtPath);
        if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
        logAudit(userId, "ISSUE_REMOTE_CERT", "Success");
        return true;
    } catch (error) { return false; }
}

function generateHSMOrganCert() {
    const p12Output = path.join(CA_DIR, `hsm_organ.p12`);
    if (fs.existsSync(p12Output)) return p12Output;

    const keyPath = path.join(CA_DIR, `hsm_organ.key`);
    const crtPath = path.join(CA_DIR, `hsm_organ.crt`);
    const caCrt = path.join(CA_DIR, 'subCA.pem');
    const rootCrt = path.join(CA_DIR, 'rootCA.pem');
    const caKey = path.join(CA_DIR, 'subCA.key');

    try {
        const cmd = `openssl ecparam -name prime256v1 -genkey -noout -out "${keyPath}" && ` +
            `openssl req -new -key "${keyPath}" -out "${keyPath}.csr" -subj "/C=VN/O=CongTyA/CN=Organ_Seal_System" && ` +
            `openssl x509 -req -in "${keyPath}.csr" -CA "${caCrt}" -CAkey "${caKey}" -set_serial 999 -out "${crtPath}" -days 3650 -sha256 && ` +
            `openssl pkcs12 -export -legacy -out "${p12Output}" -inkey "${keyPath}" -in "${crtPath}" -certfile "${caCrt}" -certfile "${rootCrt}" -passout pass:123456`;
        execSync(cmd, { stdio: 'pipe' });
        registerCertToOCSP(crtPath);
        return p12Output;
    } catch (e) { return null; }
}

generateHSMOrganCert();

async function embedSignatureAndSeal(pdfBuffer, userName, userId, fileId, signatureBase64, signType, host) {
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    pdfDoc.setKeywords(['Signed', `USER_${userId}`, `FILE_${fileId}`, `TYPE_${signType}`]);
    pdfDoc.setSubject(`Digitally Signed. Signature: ${signatureBase64.substring(0, 50)}...`);
    pdfDoc.setCreationDate(new Date());

    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const { width } = firstPage.getSize();
    
    const signTypeText = signType === "REMOTE" ? "Remote HSM" : "USB Token";
    const cleanName = userName.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d").replace(/Đ/g, "D");

    const sealText = `DA KY SO
Nguoi ky: ${cleanName}
Ma CB: ${userId}
Hinh thuc: ${signTypeText}
Thuat toan: ML-DSA-65 (PQC)
Thoi gian: ${nowVN()}`;

    const verifyUrl = `https://${host || 'localhost:3000'}/xac-thuc?fileId=${fileId}`;
    const qrContent = `${verifyUrl}\n\n` +
                      `CỔNG XÁC THỰC CHỮ KÝ SỐ QUỐC GIA\n` +
                      `Người ký: ${userName}\n` +
                      `Mã cán bộ: ${userId}\n` +
                      `Hình thức: ${signTypeText}\n` +
                      `Thuật toán: ML-DSA-65 (Kháng lượng tử)\n` +
                      `Thời gian ký: ${nowVN()}\n` +
                      `Mã tài liệu: ${fileId}`;

    let qrImage;
    try {
        const qrCodeDataUrl = await QRCode.toDataURL(qrContent, { margin: 1, width: 200 });
        const qrImageBytes = Buffer.from(qrCodeDataUrl.split(',')[1], 'base64');
        qrImage = await pdfDoc.embedPng(qrImageBytes);
    } catch (qrErr) {
        console.error("Lỗi sinh QR Code cho PDF:", qrErr);
    }

    const boxWidth = 320;
    const boxHeight = 115;
    const boxX = width - boxWidth - 20;
    const boxY = 40;

    firstPage.drawRectangle({ 
        x: boxX, 
        y: boxY, 
        width: boxWidth, 
        height: boxHeight, 
        borderColor: rgb(0.8, 0, 0), 
        borderWidth: 2 
    });

    if (qrImage) {
        firstPage.drawImage(qrImage, {
            x: boxX + 10,
            y: boxY + 17,
            width: 80,
            height: 80
        });
    }

    firstPage.drawText(sealText, { 
        x: boxX + 100, 
        y: boxY + boxHeight - 22, 
        size: 8.5, 
        color: rgb(0.8, 0, 0), 
        lineHeight: 14 
    });

    return await pdfDoc.save();
}

function generateDetachedSignatureFile(signedFileName, signatureBase64) {
    const baseName = signedFileName.slice(0, -4);
    const sigFileName = `${baseName}.sig`;
    fs.writeFileSync(path.join(SIGNED_DIR, sigFileName), signatureBase64);
    return `/download-signed/${sigFileName}`;
}

// ==========================================
// 5. CÁC API HỆ THỐNG
// ==========================================
app.post('/api/login', async (req, res) => {
    console.log(`[LOGIN ATTEMPT] UserID: ${req.body.userId}`);
    const u = await getUser(req.body.userId);
    if (u && u.password === req.body.password) {
        console.log(`[LOGIN SUCCESS] User: ${u.name}`);
        res.json(u);
    } else {
        console.log(`[LOGIN FAILED] Invalid credentials for: ${req.body.userId}`);
        res.status(401).send();
    }
});

app.get('/api/get-nonce', (req, res) => {
    const nonce = crypto.randomBytes(16).toString('hex');
    nonceCache.add(nonce);
    setTimeout(() => nonceCache.delete(nonce), 30000);
    res.json({ nonce });
});

app.post('/api/upload-pdf', upload.single('document'), async (req, res) => {
    const fileId = Date.now().toString();
    const serverHash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    const fileData = {
        buffer: req.file.buffer,
        name: req.file.originalname,
        hash: req.body.clientHash || serverHash,
        ownerId: req.body.ownerId,
        status: "PENDING",
        hoTen: req.body.hoTen || '',
        cccd: req.body.cccd || '',
        noiThuongTru: req.body.noiThuongTru || '',
        ngayGui: nowVN()
    };
    await saveCachedFile(fileId, fileData);
    res.json({ fileId, fileName: req.file.originalname });
});

app.post('/api/issue-cert', async (req, res) => {
    const user = await getUser(req.body.userId);
    if (!user) return res.status(404).send();
    const pathP12 = generateCitizenCert(req.body.userId, user.name, req.body.userPin);
    if (pathP12) { 
        await updateUser(req.body.userId, {
            hasCert: 1,
            p12Path: pathP12,
            certPin: req.body.userPin
        });
        res.json({ status: "OK" }); 
    } else {
        res.status(500).send();
    }
});

app.post('/api/revoke-cert', async (req, res) => {
    const userId = req.body.userId;
    const user = await getUser(userId);
    if (!user) return res.status(404).send();

    addToCRL(userId, user.name);
    const crtPath = path.join(KEYSTORE_DIR, `citizen_${userId}.crt`);
    if (fs.existsSync(crtPath)) {
        revokeCertInOCSP(crtPath);
    }
    await updateUser(userId, { hasCert: 0 });
    await dbRun("UPDATE signature_registry SET revoked = 1 WHERE userId = ? AND type = 'LOCAL'", [userId]);
    res.json({ status: "OK" });
});

app.post('/api/revoke-remote-cert', async (req, res) => {
    const { userId } = req.body;
    const user = await getUser(userId);
    if (!user) {
        return res.status(404).json({ status: "FAILED", message: "Không tìm thấy người dùng!" });
    }

    addToCRL(userId, user.name);
    if (user.remoteCrtPath && fs.existsSync(user.remoteCrtPath)) {
        revokeCertInOCSP(user.remoteCrtPath);
    }

    await updateUser(userId, {
        hasRemoteCert: 0,
        signPin: "",
        remoteKeyPath: "",
        remoteCrtPath: ""
    });

    await dbRun("UPDATE signature_registry SET revoked = 1 WHERE userId = ? AND type = 'REMOTE'", [userId]);
    logAudit(userId, "REVOKE_REMOTE_CERT", "Thu hồi chứng thư Remote/HSM");
    res.json({ status: "OK", message: "Đã thu hồi chứng thư Remote/HSM!" });
});

app.post('/api/issue-remote-cert', async (req, res) => {
    const { userId, signPin } = req.body;
    const user = await getUser(userId);
    if (!user) return res.status(404).send();
    if (generateRemoteCert(userId, user.name, signPin)) {
        const keyPath = path.join(REMOTE_KEYS_DIR, `remote_${userId}.key`);
        const crtPath = path.join(REMOTE_KEYS_DIR, `remote_${userId}.crt`);
        await updateUser(userId, {
            hasRemoteCert: 1,
            signPin: signPin,
            remoteKeyPath: keyPath,
            remoteCrtPath: crtPath
        });
        res.json({ status: "OK", message: "Đã tạo chứng chỉ Cloud thành công!" });
    } else {
        res.status(500).json({ status: "FAILED", message: "Lỗi hệ thống" });
    }
});

app.post('/api/remote-sign', gatewayPEPMiddleware, opaPolicyMiddleware, async (req, res) => {
    const { fileId, userId, signPin, clientHash } = req.body;
    const fileIdFinal = fileId || crypto.randomBytes(8).toString('hex');
    req.body.fileId = fileIdFinal;
    const user = await getUser(userId);

    if (!user || !user.hasRemoteCert || user.signPin !== signPin) {
        return res.json({ status: "FAILED", message: "Mã PIN Cloud không đúng!" });
    }

    const cached = await getCachedFile(fileIdFinal);
    if (!cached) return res.status(404).json({ message: "File không tồn tại" });

    try {
        const serverComputedHash = crypto.createHash('sha256').update(cached.buffer).digest('hex');
        if (serverComputedHash !== clientHash) return res.json({ status: 'FAILED', message: "Dữ liệu bị thay đổi!" });

        await revokeOldSignatures(clientHash, "REMOTE");

        const signatureBase64 = hsmSignPKCS11(clientHash, "123456");

        await saveSignature(fileIdFinal, {
            signatureId: Date.now().toString(),
            userId, timestamp: new Date().toISOString(), signature: signatureBase64,
            fileHash: clientHash, revoked: false, type: "REMOTE"
        });

        const host = req.headers.host || 'localhost:3000';
        const signedPdfBuffer = await embedSignatureAndSeal(cached.buffer, user.name, userId, fileIdFinal, signatureBase64, "REMOTE", host);
        const signedFileName = `CloudSigned_${Date.now()}.pdf`;
        const tempPdfPath = path.join(SIGNED_DIR, `temp_${signedFileName}`);
        const finalPdfPath = path.join(SIGNED_DIR, signedFileName);
        
        fs.writeFileSync(tempPdfPath, signedPdfBuffer);
        try {
            const pythonScript = path.join(__dirname, '../../tsp/python_core/sign_pdf.py');
            const hsmP12Path = path.join(CA_DIR, 'hsm_organ.p12');
            const hsmPin = '123456';
            
            console.log(`[PYTHON] Đang gọi lệnh ký HSM (Organ Seal) cho: ${signedFileName}`);
            execSync(`${getPythonCommand()} "${pythonScript}" "${tempPdfPath}" "${finalPdfPath}" "${hsmP12Path}" "${hsmPin}"`, { 
                cwd: path.join(__dirname, '../../tsp/python_core'),
                stdio: 'inherit'
            });
            
            if (fs.existsSync(tempPdfPath)) fs.unlinkSync(tempPdfPath);
        } catch(e) {
            console.error(`[PYTHON ERROR] Lỗi khi ký HSM: ${e.message}`);
            if (fs.existsSync(tempPdfPath)) fs.renameSync(tempPdfPath, finalPdfPath);
        }

        const downloadUrlSig = generateDetachedSignatureFile(signedFileName, signatureBase64);

        await saveCachedFile(fileIdFinal, {
            status: "SIGNED",
            downloadUrl: `/download-signed/${signedFileName}`,
            downloadUrlSig
        });

        globalSignedHistory.unshift({ fileName: cached.name, signer: user.name, time: nowVN(), url: `/download-signed/${signedFileName}` });
        logAudit(user.name, "SIGN_SUCCESS_HSM_PKCS11", cached.name);

        res.json({
            status: 'SUCCESS',
            fileId: fileIdFinal,
            downloadUrl: `/download-signed/${signedFileName}`,
            downloadUrlSig
        });
    } catch (e) {
        res.status(500).json({ status: "FAILED", message: "Lỗi HSM: " + e.message });
    }
});

app.post('/api/check-officer-sign-policy', async (req, res) => {
    const { fileId, officerId, signType } = req.body;

    const officer = await getUser(officerId);
    if (!officer || officer.role !== "OFFICER") {
        logAudit(officerId || "Unknown", "OPA_DECISION_DENY", "Không phải cán bộ có thẩm quyền");
        return res.status(403).json({
            status: "FAILED",
            message: "Chỉ cán bộ có thẩm quyền mới được ký hồ sơ!"
        });
    }

    const cached = await getCachedFile(fileId);
    if (!cached) {
        logAudit(officerId, "OPA_DECISION_DENY", `Không tìm thấy hồ sơ ${fileId}`);
        return res.status(404).json({
            status: "FAILED",
            message: "Không tìm thấy hồ sơ!"
        });
    }
    const action = signType === "LOCAL" ? "officer_local_sign" : "officer_remote_sign";

    const { allowed: opaAllow, error: opaError } = await callOPA({
        action,
        user: { id: officerId, role: officer.role },
        file: { id: fileId, status: cached.status, ownerId: cached.ownerId }
    });

    if (opaError) {
        logAudit(officerId, "OPA_ERROR", `Lỗi kết nối OPA: ${opaError}`);
        return res.status(500).json({
            status: "FAILED",
            message: `Lỗi hạ tầng chính sách (OPA): ${opaError}. Vui lòng chạy lệnh 'sudo systemctl restart opa' trên máy chủ VPS.`
        });
    }

    if (!opaAllow) {
        logAudit(officerId, "OPA_DECISION_DENY", `OPA/Rego deny ${action} - fileStatus=${cached.status}`);
        return res.status(403).json({
            status: "FAILED",
            message: "Hồ sơ phải được duyệt trước khi ký."
        });
    }

    return res.json({ status: "OK", message: "Policy allow" });
});

app.post('/api/officer-remote-sign', requireDPoP, async (req, res) => {
    const { fileId, officerId, hsmPin } = req.body;
    const officer = await getUser(officerId);
    if (!officer || officer.role !== "OFFICER") {
        return res.status(403).json({ status: "FAILED", message: "Chỉ cán bộ có thẩm quyền mới được ký hồ sơ!" });
    }

    const cached = await getCachedFile(fileId);
    if (!cached) {
        return res.status(404).json({ status: "FAILED", message: "Không tìm thấy hồ sơ!" });
    }

    const { allowed: opaAllow, error: opaError } = await callOPA({
        action: "officer_remote_sign",
        user: { id: officerId, role: officer.role },
        file: { id: fileId, status: cached.status, ownerId: cached.ownerId }
    });

    if (opaError) {
        return res.status(500).json({
            status: "FAILED",
            message: `Lỗi kết nối dịch vụ chính sách OPA: ${opaError}. Vui lòng chạy lệnh 'sudo systemctl restart opa' trên máy chủ VPS.`
        });
    }

    logAudit(officerId, opaAllow ? "OPA_DECISION_ALLOW" : "OPA_DECISION_DENY", 
             opaAllow ? "OPA/Rego allow officer_remote_sign" : "OPA/Rego deny officer_remote_sign");

    if (!opaAllow) {
        return res.status(403).json({ status: "FAILED", message: "OPA/Rego Blocked: Không đủ quyền hoặc hồ sơ chưa APPROVED!" });
    }

    try {
        const documentHash = crypto.createHash('sha256').update(cached.buffer).digest('hex');
        await revokeOldSignatures(documentHash, "REMOTE");

        const signatureBase64 = hsmSignPKCS11(documentHash, hsmPin || "123456");

        await saveSignature(fileId, {
            signatureId: Date.now().toString(),
            userId: officerId,
            timestamp: new Date().toISOString(),
            signature: signatureBase64,
            fileHash: documentHash,
            revoked: false,
            type: "REMOTE",
            signerCertPath: officer.remoteCrtPath
        });

        const host = req.headers.host || 'localhost:3000';
        const signedPdfBuffer = await embedSignatureAndSeal(
            cached.buffer,
            officer.name,
            officerId,
            fileId,
            signatureBase64,
            "REMOTE",
            host
        );

        const signedFileName = `CloudSigned_${Date.now()}.pdf`;
        const tempPdfPath = path.join(SIGNED_DIR, `temp_${signedFileName}`);
        const finalPdfPath = path.join(SIGNED_DIR, signedFileName);

        fs.writeFileSync(tempPdfPath, signedPdfBuffer);

        try {
            const pythonScript = path.join(__dirname, '../../tsp/python_core/sign_pdf.py');
            const hsmP12Path = path.join(CA_DIR, 'hsm_organ.p12');
            const hsmP12Pin = '123456';

            console.log(`[PYTHON] Officer đang gọi ký HSM cho: ${signedFileName}`);
            execSync(`${getPythonCommand()} "${pythonScript}" "${tempPdfPath}" "${finalPdfPath}" "${hsmP12Path}" "${hsmP12Pin}"`, {
                cwd: path.join(__dirname, '../../tsp/python_core'),
                stdio: 'inherit'
            });

            if (fs.existsSync(tempPdfPath)) fs.unlinkSync(tempPdfPath);
        } catch (e) {
            console.error(`[PYTHON ERROR] Lỗi khi ký HSM Officer: ${e.message}`);
            if (fs.existsSync(tempPdfPath)) fs.renameSync(tempPdfPath, finalPdfPath);
        }

        const downloadUrlSig = generateDetachedSignatureFile(signedFileName, signatureBase64);

        await saveCachedFile(fileId, {
            status: "SIGNED",
            signedBy: officerId,
            signType: "REMOTE",
            downloadUrl: `/download-signed/${signedFileName}`,
            downloadUrlSig
        });

        globalSignedHistory.unshift({
            fileName: cached.name,
            signer: officer.name,
            time: nowVN(),
            url: `/download-signed/${signedFileName}`
        });

        logAudit(officerId, "SIGN_SUCCESS_OFFICER_HSM", cached.name);

        res.json({
            status: "SUCCESS",
            fileId,
            downloadUrl: `/download-signed/${signedFileName}`,
            downloadUrlSig
        });

    } catch (e) {
        console.error("Officer Remote Sign Error:", e);
        res.status(500).json({ status: "FAILED", message: "Lỗi ký HSM: " + e.message });
    }
});

app.post('/api/verify-signature', async (req, res) => {
    const { documentHash, signatureBase64, certificatePEM, fileId } = req.body;
    console.log("=== DATA TỪ AGENT GỬI LÊN ===");
    console.log("Hash:", documentHash);
    console.log("FileId:", fileId);
    try {
        const cert = forge.pki.certificateFromPem(certificatePEM);
        const cn = cert.subject.getField('CN').value;

        // Lấy danh sách users từ db để khớp CN
        const dbUsers = await dbAll("SELECT userId, name FROM users");
        const matchedUserId = dbUsers
            .sort((a, b) => b.userId.length - a.userId.length)
            .find(u => cn.startsWith(u.userId + '_'))?.userId;

        if (!matchedUserId) {
            return res.json({ status: 'FAILED', message: "Không xác định được chủ thể chứng chỉ!" });
        }

        const userId = matchedUserId;
        const userName = cn.substring(userId.length + 1);
        const signerUser = await getUser(userId);

        if (!signerUser || signerUser.role !== "OFFICER") {
            return res.json({ status: 'FAILED', message: "Chỉ cán bộ có thẩm quyền mới được ký hồ sơ!" });
        }

        if (getRevokedList().find(i => i.userId === userId)) return res.json({ status: 'FAILED', message: "Chứng chỉ đã bị thu hồi!" });
        const cached = await getCachedFile(fileId);
        if (!cached) return res.json({ status: 'FAILED', message: "Không tìm thấy tài liệu gốc trên Server!" });
        if (cached.status !== "APPROVED") {
            return res.json({ status: 'FAILED', message: "Hồ sơ chưa được phê duyệt, không được phép ký!" });
        }

        const serverComputedHash = crypto.createHash('sha256').update(cached.buffer).digest('hex');
        if (serverComputedHash !== documentHash) return res.json({ status: 'FAILED', message: "Dữ liệu không đồng nhất!" });

        let isSigValid = false;
        try {
            const decodedSig = Buffer.from(signatureBase64, 'base64').toString('utf8');
            if (decodedSig.startsWith("ML-DSA-65_FIPS-204_")) {
                isSigValid = decodedSig.includes(documentHash);
            } else {
                const digest = Buffer.from(documentHash, 'hex');
                const pubKey = crypto.createPublicKey(certificatePEM);
                if (pubKey.type === 'rsa') {
                    isSigValid = crypto.verify(
                        null,
                        digest,
                        {
                            key: certificatePEM,
                            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                            saltLength: 32
                        },
                        Buffer.from(signatureBase64, 'base64')
                    );
                } else if (pubKey.type === 'ec') {
                    isSigValid = crypto.verify(
                        null,
                        digest,
                        certificatePEM,
                        Buffer.from(signatureBase64, 'base64')
                    );
                }
            }
        } catch (e) {
            console.error("Local signature validation error:", e.message);
        }

        if (isSigValid) {
            await revokeOldSignatures(documentHash, "LOCAL");

            await saveSignature(fileId, {
                signatureId: Date.now().toString(),
                userId,
                timestamp: new Date().toISOString(),
                signature: signatureBase64,
                fileHash: documentHash,
                revoked: false,
                type: "LOCAL",
                certificatePEM: certificatePEM,
                signerCertPath: signerUser?.p12Path ? path.join(KEYSTORE_DIR, `citizen_${userId}.crt`) : null
            });

            const host = req.headers.host || 'localhost:3000';
            const signedPdfBuffer = await embedSignatureAndSeal(cached.buffer, userName, userId, fileId, signatureBase64, "LOCAL", host);
            const signedFileName = `LocalSigned_${Date.now()}.pdf`;

            const tempPdfPath = path.join(SIGNED_DIR, `temp_${signedFileName}`);
            const finalPdfPath = path.join(SIGNED_DIR, signedFileName);
            fs.writeFileSync(tempPdfPath, signedPdfBuffer);
            try {
                const pythonScript = path.join(__dirname, '../../tsp/python_core/sign_pdf.py');
                const userP12Path = signerUser?.p12Path && fs.existsSync(signerUser.p12Path)
                    ? signerUser.p12Path
                    : path.join(__dirname, '../../tsp/python_core/test_cert.p12');
                const userPin = signerUser?.certPin || 'secret';
                
                console.log(`[PYTHON] Đang gọi lệnh ký Local cho: ${signedFileName} bằng cert của ${userId}`);
                execSync(`${getPythonCommand()} "${pythonScript}" "${tempPdfPath}" "${finalPdfPath}" "${userP12Path}" "${userPin}"`, { 
                    cwd: path.join(__dirname, '../../tsp/python_core'),
                    stdio: 'inherit'
                });

                if (fs.existsSync(tempPdfPath)) fs.unlinkSync(tempPdfPath);
            } catch(e) {
                console.error(`[PYTHON ERROR] Lỗi khi ký Local: ${e.message}`);
                if (fs.existsSync(tempPdfPath)) fs.renameSync(tempPdfPath, finalPdfPath);
            }

            const downloadUrlSig = generateDetachedSignatureFile(signedFileName, signatureBase64);

            await saveCachedFile(fileId, {
                status: "SIGNED",
                signedBy: userId,
                signType: "LOCAL",
                downloadUrl: `/download-signed/${signedFileName}`,
                downloadUrlSig
            });

            globalSignedHistory.unshift({
                fileName: cached.name,
                signer: userName,
                time: nowVN(),
                url: `/download-signed/${signedFileName}`
            });

            logAudit(userName, "SIGN_SUCCESS_LOCAL", cached.name);

            res.json({
                status: 'SUCCESS',
                fileId,
                downloadUrl: `/download-signed/${signedFileName}`,
                downloadUrlSig
            });
        } else {
            res.json({ status: 'FAILED', message: "Chữ ký giả mạo!" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

async function verifyPdfPath(pdfPath, originalName) {
    let pythonOut = "";
    try {
        const pythonScript = path.join(__dirname, '../../tsp/python_core/verify_pdf.py');
        pythonOut = execSync(`${getPythonCommand()} "${pythonScript}" "${pdfPath}" 2>&1`).toString();
        console.log("=== PYTHON VERIFY OUTPUT ===");
        console.log(pythonOut);
        console.log("=== END PYTHON VERIFY OUTPUT ===");
    } catch (e) {
        pythonOut = e.stdout ? e.stdout.toString() : e.message;
    }

    if (pythonOut.includes("Result: VALID")) {
        const pdfDocForRegistry = await PDFDocument.load(fs.readFileSync(pdfPath));
        const keywordsForRegistry = pdfDocForRegistry.getKeywords() || "";
        const fileIdForRegistry = keywordsForRegistry.match(/FILE_(\w+)/)?.[1];

        const sig = await getSignature(fileIdForRegistry);
        if (fileIdForRegistry && sig?.revoked) {
            saveLTVArchive({
                verify_time: new Date().toISOString(),
                document: originalName || "uploaded.pdf",
                signer: "UNKNOWN",
                timestamp_valid: pythonOut.includes("Timestamp valid: True"),
                ocsp_status: "REVOKED",
                verification_result: "REVOKED",
                certificate_path: sig?.signerCertPath || "N/A",
                reason: "Signature registry marked as revoked"
            });

            return {
                valid: false,
                message: "CHỮ KÝ ĐÃ BỊ THU HỒI!\n━━━━━━━━━━━━━━━━━━━━━━\nTài liệu từng hợp lệ về mặt mật mã, nhưng chứng thư/chữ ký đã bị thu hồi trong hệ thống.\n━━━━━━━━━━━━━━━━━━━━━━"
            };
        }
        
        const signerMatch = pythonOut.match(/Người ký \(Signer\): (.*)/);
        let signerRaw = signerMatch ? signerMatch[1].trim() : "Không rõ";
        signerRaw = signerRaw.replace(/^Common Name:\s*/i, '');
        const signerName = signerRaw.includes('_') ? signerRaw.split('_').slice(1).join(' ') : signerRaw;

        let ocspStatusForArchive = "UNKNOWN";
        let trustChainStatusForArchive = "UNKNOWN";

        if (sig?.signerCertPath) {
            const trustChainResult = checkTrustChain(sig.signerCertPath);
            trustChainStatusForArchive = trustChainResult.valid ? "VALID" : "INVALID";

            if (!trustChainResult.valid) {
                saveLTVArchive({
                    verify_time: new Date().toISOString(),
                    document: originalName || "uploaded.pdf",
                    signer: signerName,
                    timestamp_valid: pythonOut.includes("Timestamp valid: True"),
                    ocsp_status: "SKIPPED",
                    trust_chain_status: "INVALID",
                    verification_result: "INVALID",
                    certificate_path: sig?.signerCertPath || "N/A"
                });

                return {
                    valid: false,
                    message: "TRUST CHAIN KHÔNG HỢP LỆ!\n━━━━━━━━━━━━━━━━━━━━━━\nChứng chỉ người ký không thuộc Trusted Root CA của hệ thống.\n━━━━━━━━━━━━━━━━━━━━━━"
                };
            }
            const ocspResult = checkOCSP(sig.signerCertPath);
            ocspStatusForArchive = ocspResult.status;

            if (ocspResult.status === 'REVOKED') {
                saveLTVArchive({
                    verify_time: new Date().toISOString(),
                    document: originalName || "uploaded.pdf",
                    signer: signerName,
                    timestamp_valid: pythonOut.includes("Timestamp valid: True"),
                    ocsp_status: "REVOKED",
                    verification_result: "REVOKED",
                    certificate_path: sig?.signerCertPath || "N/A"
                });

                return {
                    valid: false,
                    message: `CHỨNG CHỈ ĐÃ BỊ THU HỒI (OCSP)!\n━━━━━━━━━━━━━━━━━━━━━━\n👤 Người ký: ${signerName}\n━━━━━━━━━━━━━━━━━━━━━━`
                };
            }

            if (ocspResult.status === 'ERROR') {
                return { valid: false, message: "Không kiểm tra được OCSP responder!" };
            }
        }

        const intactMatch = pythonOut.match(/Toàn vẹn dữ liệu \(Intact\): (.*)/);
        const validMatch  = pythonOut.match(/Xác thực mật mã \(Valid\): (.*)/);
        const intact = intactMatch ? intactMatch[1].trim() : 'Hợp lệ';
        const valid  = validMatch  ? validMatch[1].trim()  : 'Thành công';

        const formatted = `Tài liệu đã được xác thực hợp lệ!\n`
            + `━━━━━━━━━━━━━━━━━━━━━━\n`
            + `Toàn vẹn dữ liệu: ${intact}\n`
            + `Xác thực mật mã:  ${valid}\n`
            + `Người ký: ${signerName}\n`
            + `Trạng thái chứng chỉ: Còn hiệu lực\n`
            + `Trusted Root Chain: Hợp lệ\n`
            + `Phương thức: pyHanko / CA nội bộ\n`
            + `━━━━━━━━━━━━━━━━━━━━━━`;
        
        saveLTVArchive({
            verify_time: new Date().toISOString(),
            document: originalName || "uploaded.pdf",
            signer: signerName,
            timestamp_valid: pythonOut.includes("Timestamp valid: True"),
            ocsp_status: ocspStatusForArchive,
            trust_chain_status: trustChainStatusForArchive,
            verification_result: "VALID",
            certificate_path: sig?.signerCertPath || "N/A"
        });

        return { valid: true, signer: signerName, message: formatted };
    } else if (pythonOut.includes("Result: INVALID") || pythonOut.includes("LỖI HỆ THỐNG")) {
        const errMatch = pythonOut.match(/LỖI HỆ THỐNG KHI XÁC THỰC: (.*)/);
        const detail = errMatch ? errMatch[1].trim() : 'Xác minh mật mã thất bại.';
        return { valid: false, message: `Tài liệu không hợp lệ!\n━━━━━━━━━━━━━━━━━━━━━━\n${detail}\n━━━━━━━━━━━━━━━━━━━━━━` };
    }

    // Fallback nếu không khớp định dạng pyHanko
    const pdfDoc = await PDFDocument.load(fs.readFileSync(pdfPath));
    const keywordsStr = pdfDoc.getKeywords() || "";

    if (!keywordsStr.includes('Signed')) {
        return { valid: false, message: "FILE CHƯA ĐƯỢC KÝ HOẶC BỊ SỬA METADATA!" };
    }

    const userId = keywordsStr.match(/USER_([A-Za-z0-9_]+)/)?.[1];
    const fileId = keywordsStr.match(/FILE_(\w+)/)?.[1];
    const signType = keywordsStr.match(/TYPE_(\w+)/)?.[1];

    if (!userId || !fileId || !signType) {
        return { valid: false, message: "Metadata không đầy đủ hoặc bị hỏng!" };
    }

    const sig = await getSignature(fileId);
    if (!sig) return { valid: false, message: "Không tìm thấy dữ liệu chữ ký trên hệ thống (Registry)!" };

    if (sig.revoked) return { valid: false, message: `Tài liệu này đã bị thu hồi do có phiên bản Ký ${signType} mới hơn thay thế!` };
    if (sig.userId !== userId) return { valid: false, message: "Không khớp ID người ký!" };

    const isRevoked = getRevokedList().find(i => i.userId === userId);
    if (isRevoked) return { valid: false, message: `CHỨNG CHỈ ĐÃ BỊ THU HỒI!\n👤 ${isRevoked.name}\n⏰ ${isRevoked.revokedAt}` };

    let isValidSignature = false;
    try {
        const decodedSig = Buffer.from(sig.signature, 'base64').toString('utf8');
        if (decodedSig.startsWith("ML-DSA-65_FIPS-204_")) {
            isValidSignature = decodedSig.includes(sig.fileHash);
        } else {
            const digest = Buffer.from(sig.fileHash, 'hex');
            if (signType === "REMOTE") {
                const publicKeyPem = getPublicKeyPEM();
                const pubKey = crypto.createPublicKey(publicKeyPem);
                if (pubKey.type === 'rsa') {
                    isValidSignature = crypto.verify(
                        null,
                        digest,
                        {
                            key: publicKeyPem,
                            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                            saltLength: 32
                        },
                        Buffer.from(sig.signature, 'base64')
                    );
                } else if (pubKey.type === 'ec') {
                    isValidSignature = crypto.verify(null, digest, publicKeyPem, Buffer.from(sig.signature, 'base64'));
                }
            } else if (signType === "LOCAL") {
                if (!sig.certificatePEM) {
                    return { valid: false, message: "Không tìm thấy chứng chỉ của người ký trong hệ thống!" };
                }
                const cleanCertPem = sig.certificatePEM.trim();
                const pubKey = crypto.createPublicKey(cleanCertPem);
                if (pubKey.type === 'rsa') {
                    isValidSignature = crypto.verify(
                        null,
                        digest,
                        {
                            key: cleanCertPem,
                            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                            saltLength: 32
                        },
                        Buffer.from(sig.signature, 'base64')
                    );
                } else if (pubKey.type === 'ec') {
                    isValidSignature = crypto.verify(null, digest, cleanCertPem, Buffer.from(sig.signature, 'base64'));
                }
            }
        }
    } catch (cryptoErr) {
        console.error("Lỗi Crypto Verify:", cryptoErr);
        return { valid: false, message: "Lỗi giải mã chữ ký!" };
    }

    if (!isValidSignature) {
        return { valid: false, message: "Xác minh mật mã thất bại! Dữ liệu có thể đã bị can thiệp." };
    }

    const dbUser = await getUser(userId);
    return {
        valid: true,
        message: `✔️ Tài liệu hợp lệ (Phương thức: ${signType})\nKhông bị thu hồi và toàn vẹn dữ liệu.`,
        signer: `${dbUser?.name || "Unknown"} (${userId})`
    };
}

app.post('/api/verify-only', upload.single('document'), async (req, res) => {
    try {
        const tempVerifyPath = path.join(__dirname, 'temp_verify_' + Date.now() + '.pdf');
        fs.writeFileSync(tempVerifyPath, req.file.buffer);
        const result = await verifyPdfPath(tempVerifyPath, req.file.originalname);
        try {
            fs.unlinkSync(tempVerifyPath);
        } catch (e) {}
        return res.json(result);
    } catch (error) {
        console.error("Lỗi Verify General:", error);
        res.json({ valid: false, message: "Lỗi Verify: Không đọc được PDF hoặc hệ thống lỗi." });
    }
});

app.get('/api/verify-by-id/:fileId', async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const cached = await getCachedFile(fileId);
        if (!cached) {
            return res.json({ valid: false, message: "Không tìm thấy hồ sơ/tài liệu trên hệ thống!" });
        }
        
        if (cached.status !== "SIGNED") {
            return res.json({ 
                valid: false, 
                message: `Hồ sơ "${cached.name}" chưa được ký số.\nTrạng thái hiện tại: ${cached.status}` 
            });
        }
        
        const signedFileName = path.basename(cached.downloadUrl);
        const signedFilePath = path.join(SIGNED_DIR, signedFileName);
        
        if (!fs.existsSync(signedFilePath)) {
            return res.json({ valid: false, message: "Không tìm thấy tệp đã ký trên máy chủ!" });
        }
        
        const result = await verifyPdfPath(signedFilePath, cached.name);
        return res.json(result);
    } catch (error) {
        console.error("Lỗi verify-by-id:", error);
        res.json({ valid: false, message: "Lỗi hệ thống khi tra cứu chữ ký!" });
    }
});

app.get('/api/history', (req, res) => res.json(globalSignedHistory));

app.get('/download-cert/:userId', async (req, res) => {
    const user = await getUser(req.params.userId);
    if (!user || !user.p12Path) return res.status(404).send();
    res.setHeader('Content-Type', 'application/x-pkcs12');
    res.download(user.p12Path);
});

app.get('/download-signed/:name', (req, res) => res.download(path.join(SIGNED_DIR, req.params.name)));

// ==========================================
// 6. GIAO DIỆN NGƯỜI DÙNG (FRONTEND)
// ==========================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));

// ==========================================
// API CHO CÁN BỘ (OFFICER)
// ==========================================
app.get('/api/pending-requests', async (req, res) => {
    const rows = await dbAll("SELECT * FROM pdf_cache WHERE status IN ('PENDING', 'APPROVED', 'SIGNED')");
    const pending = rows.map(file => ({
        fileId: file.fileId,
        hoTen: file.hoTen || 'N/A',
        cccd: file.cccd || 'N/A',
        noiThuongTru: file.noiThuongTru || 'N/A',
        ngayGui: file.ngayGui || 'N/A',
        status: file.status || 'PENDING',
        hash: file.hash,
        downloadUrl: file.downloadUrl || '',
        downloadUrlSig: file.downloadUrlSig || ''
    }));
    res.json(pending);
});

app.get('/api/file-info/:fileId', async (req, res) => {
    const file = await getCachedFile(req.params.fileId);
    if (!file) return res.status(404).json({ error: 'File not found' });
    res.json({
        fileId: req.params.fileId,
        hoTen: file.hoTen || '',
        cccd: file.cccd || '',
        ngaySinh: file.ngaySinh || '',
        gioiTinh: file.gioiTinh || '',
        noiThuongTru: file.noiThuongTru || '',
        mucDich: file.mucDich || '',
        email: file.email || '',
        phone: file.phone || '',
        ghiChu: file.ghiChu || '',
        ngayGui: file.ngayGui || '',
        status: file.status,
        hash: file.hash,
        downloadUrl: file.downloadUrl || '',
        downloadUrlSig: file.downloadUrlSig || ''
    });
});

app.get('/api/citizen-lookup/:cccd', async (req, res) => {
    const cccd = req.params.cccd;
    const citizen = await dbGet("SELECT * FROM users WHERE cccd = ? AND role = 'Citizen'", [cccd]);
    if (citizen) {
        return res.json({
            hoTen: citizen.hoTen || citizen.name,
            cccd: citizen.cccd,
            ngaySinh: citizen.ngaySinh,
            gioiTinh: citizen.gioiTinh,
            noiThuongTru: citizen.noiThuongTru
        });
    }
    res.json({
        hoTen: 'Không tìm thấy',
        cccd: cccd,
        ngaySinh: 'N/A',
        gioiTinh: 'N/A',
        noiThuongTru: 'Không có dữ liệu'
    });
});

app.post('/api/approve', async (req, res) => {
    const { fileId, officerId } = req.body;
    const officer = await getUser(officerId);
    if (!officer || officer.role !== "OFFICER") {
        return res.status(403).json({ status: "FAILED", message: "Chỉ cán bộ mới có quyền phê duyệt!" });
    }
    const file = await getCachedFile(fileId);
    if (!file) return res.status(404).json({ status: "FAILED", message: "Không tìm thấy hồ sơ!" });
    
    await saveCachedFile(fileId, {
        status: "APPROVED",
        approvedBy: officerId,
        approvedAt: new Date().toISOString()
    });
    logAudit(officerId, "APPROVE", `Đã duyệt hồ sơ ${fileId}`);
    res.json({ status: "OK", message: "Đã phê duyệt hồ sơ!" });
});

app.post('/api/reject', async (req, res) => {
    const { fileId, officerId, reason } = req.body;
    const officer = await getUser(officerId);
    if (!officer || officer.role !== "OFFICER") {
        return res.status(403).json({ status: "FAILED", message: "Chỉ cán bộ mới có quyền từ chối!" });
    }
    const file = await getCachedFile(fileId);
    if (!file) return res.status(404).json({ status: "FAILED", message: "Không tìm thấy hồ sơ!" });
    
    await saveCachedFile(fileId, {
        status: "REJECTED",
        rejectedBy: officerId,
        rejectReason: reason || "Thông tin không hợp lệ",
        rejectedAt: new Date().toISOString()
    });
    logAudit(officerId, "REJECT", `Từ chối hồ sơ ${fileId}: ${reason}`);
    res.json({ status: "OK", message: "Đã từ chối hồ sơ!" });
});

app.get('/api/public-key/:userId', async (req, res) => {
    const userId = req.params.userId;
    const certPath = path.join(KEYSTORE_DIR, `citizen_${userId}.crt`);
    if (fs.existsSync(certPath)) {
        res.setHeader('Content-Type', 'application/x-pem-file');
        res.sendFile(certPath);
    } else {
        const subCaPath = path.join(CA_DIR, 'subCA.pem');
        if (fs.existsSync(subCaPath)) {
            res.setHeader('Content-Type', 'application/x-pem-file');
            res.sendFile(subCaPath);
        } else {
            res.status(404).json({ message: "Không tìm thấy chứng chỉ" });
        }
    }
});

// ==========================================
// MIDDLEWARE GIẢ LẬP FIREWALL
// ==========================================
function firewallF2Middleware(req, res, next) {
    const allowedIPs = ['::1', '127.0.0.1', '::ffff:127.0.0.1'];
    const clientIP = req.ip || req.connection.remoteAddress;
    if (!allowedIPs.includes(clientIP)) {
        logAudit('SYSTEM', 'FIREWALL_F2_BLOCKED', `Blocked IP: ${clientIP}`);
        return res.status(403).json({ status: "FAILED", message: "F2 Firewall: Chỉ chấp nhận kết nối từ Gateway (DMZ)." });
    }
    next();
}

function firewallF3Middleware(req, res, next) {
    const allowedIPs = ['::1', '127.0.0.1', '::ffff:127.0.0.1'];
    const clientIP = req.ip || req.connection.remoteAddress;
    if (!allowedIPs.includes(clientIP)) {
        logAudit('SYSTEM', 'FIREWALL_F3_BLOCKED', `Blocked IP: ${clientIP}`);
        return res.status(403).json({ status: "FAILED", message: "F3 Firewall: Chỉ chấp nhận lệnh ký từ máy Cán bộ (Private)." });
    }
    next();
}

// ==========================================
// ROUTE GIAO DIỆN
// ==========================================
app.get('/officer', (req, res) => res.sendFile(path.join(__dirname, '../frontend/officer.html')));
app.get('/xac-thuc', (req, res) => res.sendFile(path.join(__dirname, '../frontend/xac-thuc.html')));
app.get('/bank', (req, res) => res.redirect('/xac-thuc'));

app.get('/api/my-requests/:userId', async (req, res) => {
    const userId = req.params.userId;
    const rows = await dbAll("SELECT * FROM pdf_cache WHERE ownerId = ?", [userId]);
    const myRequests = rows.map(file => ({
        fileId: file.fileId,
        fileName: file.name,
        hash: file.hash,
        status: file.status || 'PENDING',
        rejectReason: file.rejectReason || '',
        downloadUrl: file.downloadUrl || '',
        downloadUrlSig: file.downloadUrlSig || ''
    }));
    res.json(myRequests);
});

const https = require('https');
const keyPathSSL = path.join(__dirname, 'server.key');
const certPathSSL = path.join(__dirname, 'server.cert');

const isHttpOnly = process.env.HTTP_ONLY === 'true';

if (!isHttpOnly && (!fs.existsSync(keyPathSSL) || !fs.existsSync(certPathSSL))) {
    try {
        console.log("🔒 Đang tự động sinh chứng chỉ SSL/TLS Self-Signed cho HTTPS...");
        execSync(`openssl req -nodes -new -x509 -keyout "${keyPathSSL}" -out "${certPathSSL}" -days 365 -subj "/C=VN/O=Dev/CN=localhost"`, { stdio: 'inherit' });
    } catch (e) {
        console.warn("⚠️ Cảnh báo: Không thể sinh chứng chỉ SSL/TLS tự động:", e.message);
    }
}

const serverOptions = {};
if (!isHttpOnly && fs.existsSync(keyPathSSL) && fs.existsSync(certPathSSL)) {
    serverOptions.key = fs.readFileSync(keyPathSSL);
    serverOptions.cert = fs.readFileSync(certPathSSL);
}

const server = serverOptions.key ? https.createServer(serverOptions, app) : app;

server.listen(port, () => {
    const protocol = serverOptions.key ? 'https' : 'http';
    console.log(`🚀 Server chạy thành công tại: ${protocol}://localhost:${port}`);
});