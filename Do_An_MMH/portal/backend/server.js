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
const port = 3000;

// Thiết lập môi trường cho SoftHSM2
const hsmConfigPath = path.join(__dirname, '../../ca-infrastructure/storage/softhsm2/softhsm2.conf');
process.env.SOFTHSM2_CONF = hsmConfigPath;

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
// 1. KHỞI TẠO CẤU TRÚC THƯ MỤC
// ==========================================
const KEYSTORE_DIR = path.join(__dirname, '../../ca-infrastructure/storage/keystore');
const CA_DIR = path.join(__dirname, '../../ca-infrastructure/storage/ca-authority');
const SIGNED_DIR = path.join(__dirname, '../../ca-infrastructure/storage/signed_documents');
const HISTORY_DIR = path.join(KEYSTORE_DIR, 'history');
const REMOTE_KEYS_DIR = path.join(KEYSTORE_DIR, 'remote_keys');
const LTV_ARCHIVE_DIR = path.join(__dirname, '../../verifier/ltv_archive');
const CRL_FILE = path.join(KEYSTORE_DIR, 'crl.json');
const REGISTRY_FILE = path.join(__dirname, 'signatureRegistry.json');

[KEYSTORE_DIR, CA_DIR, SIGNED_DIR, HISTORY_DIR, REMOTE_KEYS_DIR, LTV_ARCHIVE_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

if (!fs.existsSync(CRL_FILE)) fs.writeFileSync(CRL_FILE, JSON.stringify([]));

const upload = multer({ storage: multer.memoryStorage() });

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

// ==========================================
// 2. CƠ SỞ DỮ LIỆU & CACHE
// ==========================================
const users = {
    "officer_01": {
        role: "OFFICER",
        name: "Can Bo Cong An Phuong",
        password: "456",
        hasCert: false,
        p12Path: "",
        hasRemoteCert: false,
        signPin: "",
        remoteKeyPath: "",
        remoteCrtPath: ""
    },
    "0522 0100 7777": {
        role: "Citizen",
        name: "Nguyễn Văn A",
        hoTen: "Nguyễn Văn A",
        cccd: "0522 0100 7777",
        ngaySinh: "2003-04-15",
        gioiTinh: "Nam",
        noiThuongTru: "123 Lê Lợi, Phường Linh Trung, TP. Thủ Đức",
        email: "nguyenvana@example.com",
        phone: "0901234567",
        password: "123456",
        hasCert: false,
        p12Path: "",
        hasRemoteCert: false,
        signPin: "",
        remoteKeyPath: "",
        remoteCrtPath: ""
    },
    "0522 0100 8888": {
        role: "Citizen",
        name: "Trần Thị B",
        hoTen: "Trần Thị B",
        cccd: "0522 0100 8888",
        ngaySinh: "2003-09-20",
        gioiTinh: "Nu",
        noiThuongTru: "456 Nguyễn Huệ, Phường Linh Chiểu, TP. Thủ Đức",
        email: "tranthib@example.com",
        phone: "0912345678",
        password: "123456",
        hasCert: false,
        p12Path: "",
        hasRemoteCert: false,
        signPin: "",
        remoteKeyPath: "",
        remoteCrtPath: ""
    }
};

let signatureRegistry = {};
let pdfCache = {};
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

if (fs.existsSync(REGISTRY_FILE)) {
    try { signatureRegistry = JSON.parse(fs.readFileSync(REGISTRY_FILE)); }
    catch (e) { signatureRegistry = {}; }
}

function saveRegistry() {
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(signatureRegistry, null, 2));
}

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

        return data.result === true;
    } catch (e) {
        console.error("[OPA] Error:", e.message);
        return false;
    }
}

function getRequestUrlForDpop(req) {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
}

async function requireDPoP(req, res, next) {
    try {
        const dpopProof = req.headers['dpop'];

        if (!dpopProof) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                "Missing DPoP proof"
            );

            return res.status(401).json({
                status: "FAILED",
                message: "DPoP proof is required."
            });
        }

        const parts = dpopProof.split('.');
        if (parts.length !== 3) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                "Invalid DPoP JWT format"
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Invalid DPoP proof format."
            });
        }

        const headerJson = JSON.parse(
            Buffer.from(parts[0], 'base64url').toString('utf8')
        );

        if (headerJson.typ !== "dpop+jwt") {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                "Invalid DPoP typ"
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Invalid DPoP typ."
            });
        }

        if (!headerJson.jwk) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                "Missing DPoP public JWK"
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Missing DPoP public JWK."
            });
        }

        const { jwtVerify, importJWK, calculateJwkThumbprint } = await getJose();

        const publicKey = await importJWK(
            headerJson.jwk,
            headerJson.alg || "ES256"
        );

        const { payload } = await jwtVerify(dpopProof, publicKey, {
            typ: "dpop+jwt"
        });

        const expectedHtm = req.method.toUpperCase();
        const expectedHtu = getRequestUrlForDpop(req);

        if (payload.htm !== expectedHtm) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                `Invalid htm: expected=${expectedHtm}, got=${payload.htm}`
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Invalid DPoP htm."
            });
        }

        if (payload.htu !== expectedHtu) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                `Invalid htu: expected=${expectedHtu}, got=${payload.htu}`
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Invalid DPoP htu."
            });
        }

        const now = Math.floor(Date.now() / 1000);
        const maxAgeSeconds = 120;

        if (!payload.iat || Math.abs(now - payload.iat) > maxAgeSeconds) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                "DPoP proof expired or invalid iat"
            );

            return res.status(401).json({
                status: "FAILED",
                message: "DPoP proof expired."
            });
        }

        if (!payload.jti) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "DPOP_DENY",
                "Missing DPoP jti"
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Missing DPoP jti."
            });
        }

        if (dpopJtiCache.has(payload.jti)) {
            logAudit(
                req.body?.officerId || req.body?.userId || "Unknown",
                "REPLAY_ATTACK_BLOCKED",
                `Reused DPoP jti: ${payload.jti}`
            );

            return res.status(401).json({
                status: "FAILED",
                message: "Replay Attack Blocked: DPoP jti was already used."
            });
        }

        dpopJtiCache.set(
            payload.jti,
            Date.now() + maxAgeSeconds * 1000
        );

        req.dpop = {
    jti: payload.jti,
    jwkThumbprint: await calculateJwkThumbprint(headerJson.jwk)
};

logAudit(
    req.body?.officerId || req.body?.userId || "Unknown",
    "DPOP_ALLOW",
    `DPoP verified jti=${payload.jti}`
);

next();

    } catch (e) {
        console.error("[DPOP] Error:", e.message);

        logAudit(
            req.body?.officerId || req.body?.userId || "Unknown",
            "DPOP_DENY",
            e.message
        );

        return res.status(401).json({
            status: "FAILED",
            message: "Invalid DPoP proof."
        });
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

        execSync(
            `openssl verify -CAfile "${rootCA}" -untrusted "${subCA}" "${certPath}"`,
            { stdio: 'pipe' }
        );

        console.log("=== TRUST CHAIN RESULT: VALID ===");

        return {
            valid: true,
            message: "TRUST_CHAIN_VALID"
        };

    } catch (e) {

        console.log("=== TRUST CHAIN RESULT: INVALID ===");

        if (e.stdout) {
            console.log(e.stdout.toString());
        }

        return {
            valid: false,
            message: "TRUST_CHAIN_INVALID"
        };
    }
}

function revokeOldSignatures(fileHash, signType) {
    for (const key in signatureRegistry) {
        if (signatureRegistry[key].fileHash === fileHash) {
            signatureRegistry[key].revoked = true;
            logAudit("SYSTEM", "REVOKE_OLD_SIG", `Revoked old ${signType} signature for file hash ${fileHash}`);
        }
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

function opaPolicyMiddleware(req, res, next) {
    const { userId, fileId } = req.body;
    const user = users[userId];
    const cachedFile = pdfCache[fileId];

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

    if (!libPath) {
        console.warn("⚠️ fallback local key (No HSM found)");
        const privateKeyPem = fs.readFileSync(path.join(CA_DIR, 'subCA.key'), 'utf8');
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(Buffer.from(dataHashHex, 'hex'));
        return sign.sign(privateKeyPem, 'base64');
    }

    let mod, session;
    try {
        mod = Module.load(libPath, "SoftHSM");
        mod.initialize();
        const slots = mod.getSlots(true);
        let slot = null;

        for (let i = 0; i < slots.length; i++) {
            const s = slots.items(i);
            try {
                if (s.getToken().label.trim() === "CloudHSM") { slot = s; break; }
            } catch (e) { }
        }

        if (!slot) throw new Error("Không tìm thấy slot CloudHSM");
        session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);

        try { session.login(pin); } catch (e) {
            if (!e.message.includes("CKR_USER_ALREADY_LOGGED_IN")) throw e;
        }

        let privateKey = session.find({ class: graphene.ObjectClass.PRIVATE_KEY, label: "mykey" }).items(0);
        if (!privateKey) privateKey = session.find({ class: graphene.ObjectClass.PRIVATE_KEY, id: Buffer.from([0x01]) }).items(0);
        if (!privateKey) throw new Error("Không tìm thấy private key");

        let signer;
        try {
            signer = session.createSign({
                name: "ECDSA"
            }, privateKey);
        } catch (e) {
            const pssParams = new graphene.RsaPssParams(
                graphene.MechanismEnum.SHA256,
                graphene.RsaMgf.MGF1_SHA256,
                32
            );
            signer = session.createSign({
                name: "RSA_PKCS_PSS",
                params: pssParams
            }, privateKey);
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
        return []; // Nếu file bị rỗng hoặc lỗi JSON thì tự động trả về mảng rỗng
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
        const ocspIndex = path.join(
            __dirname,
            '../../ca-infrastructure/ocsp/index.txt'
        );

        const serial = execSync(
            `openssl x509 -in "${certPath}" -noout -serial`
        ).toString().trim().replace('serial=', '').toUpperCase();

        const subject = execSync(
            `openssl x509 -in "${certPath}" -noout -subject -nameopt compat`
        ).toString().trim().replace(/^subject=\s*/, '');

        const endDateRaw = execSync(
            `openssl x509 -in "${certPath}" -noout -enddate`
        ).toString().trim().replace('notAfter=', '');

        const expiry = formatOpenSSLDate(new Date(endDateRaw));

        let lines = [];

        if (fs.existsSync(ocspIndex)) {
            lines = fs.readFileSync(ocspIndex, 'utf8')
                .split(/\r?\n/)
                .filter(Boolean)
                .filter(line => {
                    const cols = line.split('\t');

                    // Bỏ dòng trùng serial
                    if (cols[3] === serial) return false;

                    // Bỏ dòng trùng subject để tránh OpenSSL lỗi name index
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
        const ocspIndex = path.join(
            __dirname,
            '../../ca-infrastructure/ocsp/index.txt'
        );

        const serial = execSync(
            `openssl x509 -in "${certPath}" -noout -serial`
        ).toString().trim().replace('serial=', '').toUpperCase();

        const subject = execSync(
            `openssl x509 -in "${certPath}" -noout -subject -nameopt compat`
        ).toString().trim().replace(/^subject=\s*/, '');

        const endDateRaw = execSync(
            `openssl x509 -in "${certPath}" -noout -enddate`
        ).toString().trim().replace('notAfter=', '');

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

                    // Xóa dòng trùng subject nhưng khác serial để tránh lỗi OpenSSL name index
                    if (cols[5] === subject && cols[3] !== serial) {
                        return false;
                    }

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

        users[userId].hasRemoteCert = true;
        users[userId].signPin = pin;
        users[userId].remoteKeyPath = keyPath;
        users[userId].remoteCrtPath = crtPath;
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

// Khởi tạo chứng chỉ HSM Organ ngay khi start (dùng cho organ seal)
generateHSMOrganCert();

async function embedSignatureAndSeal(pdfBuffer, userName, userId, fileId, signatureBase64, signType, host) {
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    pdfDoc.setKeywords(['Signed', `USER_${userId}`, `FILE_${fileId}`, `TYPE_${signType}`]);
    pdfDoc.setSubject(`Digitally Signed. Signature: ${signatureBase64.substring(0, 50)}...`);
    pdfDoc.setCreationDate(new Date());

    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const { width } = firstPage.getSize();
    
    const signTypeText = signType === "REMOTE"
        ? "Remote HSM"
        : "USB Token";

    // Loại bỏ dấu tiếng Việt để tránh lỗi font Standard trong pdf-lib
    const cleanName = userName
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/đ/g, "d")
        .replace(/Đ/g, "D");

    const sealText =
    `DA KY SO
Nguoi ky: ${cleanName}
Ma CB: ${userId}
Hinh thuc: ${signTypeText}
Thuat toan: ML-DSA-65 (PQC)
Thoi gian: ${nowVN()}`;

    // Tạo nội dung mã QR (mã QR hỗ trợ tiếng Việt UTF-8 đầy đủ, kèm liên kết trực tuyến)
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

    // Thiết lập khung chữ ký to hơn để chứa cả QR Code và Text (Rộng 320, Cao 115)
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

    // Vẽ QR Code ở bên trái khung
    if (qrImage) {
        firstPage.drawImage(qrImage, {
            x: boxX + 10,
            y: boxY + 17,
            width: 80,
            height: 80
        });
    }

    // Vẽ text thông tin chữ ký ở bên phải khung
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
    const baseName = signedFileName.slice(0, -4); // Remove .pdf
    const sigFileName = `${baseName}.sig`;

    // Tạo file .sig chứa base64 signature
    fs.writeFileSync(path.join(SIGNED_DIR, sigFileName), signatureBase64);

    return `/download-signed/${sigFileName}`;
}

// ==========================================
// 5. CÁC API HỆ THỐNG
// ==========================================

app.post('/api/login', (req, res) => {
    console.log(`[LOGIN ATTEMPT] UserID: ${req.body.userId}`);
    const u = users[req.body.userId];
    if (u && u.password === req.body.password) {
        console.log(`[LOGIN SUCCESS] User: ${u.name}`);
        res.json({ userId: req.body.userId, ...u });
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

app.post('/api/upload-pdf', upload.single('document'), (req, res) => {
    const fileId = Date.now().toString();
    const serverHash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    pdfCache[fileId] = {
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
    res.json({ fileId, fileName: req.file.originalname });
});

app.post('/api/issue-cert', (req, res) => {
    const pathP12 = generateCitizenCert(req.body.userId, users[req.body.userId].name, req.body.userPin);
    if (pathP12) { 
        users[req.body.userId].hasCert = true; 
        users[req.body.userId].p12Path = pathP12;
        users[req.body.userId].certPin = req.body.userPin; // Lưu PIN để dùng khi ký PDF
        res.json({ status: "OK" }); 
    }
    else res.status(500).send();
});

app.post('/api/revoke-cert', (req, res) => {
    const userId = req.body.userId;
    const user = users[userId];

    addToCRL(userId, user.name);

    const crtPath = path.join(KEYSTORE_DIR, `citizen_${userId}.crt`);

    if (fs.existsSync(crtPath)) {
        revokeCertInOCSP(crtPath);
    }

    user.hasCert = false;

    for (const key in signatureRegistry) {
        if (signatureRegistry[key].userId === userId && signatureRegistry[key].type === "LOCAL") {
            signatureRegistry[key].revoked = true;
        }
    }

    saveRegistry();

    res.json({ status: "OK" });
});

app.post('/api/revoke-remote-cert', (req, res) => {
    const { userId } = req.body;
    const user = users[userId];

    if (!user) {
        return res.status(404).json({
            status: "FAILED",
            message: "Không tìm thấy người dùng!"
        });
    }

    addToCRL(userId, user.name);

    if (user.remoteCrtPath && fs.existsSync(user.remoteCrtPath)) {
    revokeCertInOCSP(user.remoteCrtPath);
    }

    user.hasRemoteCert = false;
    user.signPin = "";
    user.remoteKeyPath = "";
    user.remoteCrtPath = "";

    for (const key in signatureRegistry) {
        if (signatureRegistry[key].userId === userId && signatureRegistry[key].type === "REMOTE") {
            signatureRegistry[key].revoked = true;
        }
    }
    saveRegistry();

    logAudit(userId, "REVOKE_REMOTE_CERT", "Thu hồi chứng thư Remote/HSM và các chữ ký Remote liên quan");

    res.json({
        status: "OK",
        message: "Đã thu hồi chứng thư Remote/HSM!"
    });
});

app.post('/api/issue-remote-cert', (req, res) => {
    const { userId, signPin } = req.body;
    const user = users[userId];
    if (generateRemoteCert(userId, user.name, signPin)) {
        res.json({ status: "OK", message: "Đã tạo chứng chỉ Cloud thành công!" });
    } else res.status(500).json({ status: "FAILED", message: "Lỗi hệ thống" });
});

app.post('/api/remote-sign', gatewayPEPMiddleware, opaPolicyMiddleware, async (req, res) => {
    const { fileId, userId, signPin, clientHash } = req.body;
    const fileIdFinal = fileId || crypto.randomBytes(8).toString('hex');
    req.body.fileId = fileIdFinal;
    const user = users[userId];

    if (!user || !user.hasRemoteCert || user.signPin !== signPin) {
        return res.json({ status: "FAILED", message: "Mã PIN Cloud không đúng!" });
    }

    const cached = pdfCache[fileIdFinal];
    if (!cached) return res.status(404).json({ message: "File không tồn tại" });

    try {
        const serverComputedHash = crypto.createHash('sha256').update(cached.buffer).digest('hex');
        if (serverComputedHash !== clientHash) return res.json({ status: 'FAILED', message: "Dữ liệu bị thay đổi!" });

        revokeOldSignatures(clientHash, "REMOTE");

        const signatureBase64 = hsmSignPKCS11(clientHash, "123456");

        signatureRegistry[fileIdFinal] = {
            signatureId: Date.now().toString(),
            userId, timestamp: new Date().toISOString(), signature: signatureBase64,
            fileHash: clientHash, revoked: false, type: "REMOTE"
        };

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
            execSync(`python3 "${pythonScript}" "${tempPdfPath}" "${finalPdfPath}" "${hsmP12Path}" "${hsmPin}"`, { 
                cwd: path.join(__dirname, '../../tsp/python_core'),
                stdio: 'inherit'
            });
            
            if (fs.existsSync(tempPdfPath)) fs.unlinkSync(tempPdfPath);
        } catch(e) {
            console.error(`[PYTHON ERROR] Lỗi khi ký HSM: ${e.message}`);
            if (fs.existsSync(tempPdfPath)) fs.renameSync(tempPdfPath, finalPdfPath);
        }
        saveRegistry();

        const downloadUrlSig = generateDetachedSignatureFile(signedFileName, signatureBase64);

        cached.status = "SIGNED";
        cached.downloadUrl = `/download-signed/${signedFileName}`;
        cached.downloadUrlSig = downloadUrlSig;

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

    const officer = users[officerId];
    if (!officer || officer.role !== "OFFICER") {
        logAudit(officerId || "Unknown", "OPA_DECISION_DENY", "Không phải cán bộ có thẩm quyền");
        return res.status(403).json({
            status: "FAILED",
            message: "Chỉ cán bộ có thẩm quyền mới được ký hồ sơ!"
        });
    }

    const cached = pdfCache[fileId];
    if (!cached) {
        logAudit(officerId, "OPA_DECISION_DENY", `Không tìm thấy hồ sơ ${fileId}`);
        return res.status(404).json({
            status: "FAILED",
            message: "Không tìm thấy hồ sơ!"
        });
    }

    const action = signType === "LOCAL"
        ? "officer_local_sign"
        : "officer_remote_sign";

    const opaAllow = await callOPA({
        action,
        user: {
            id: officerId,
            role: officer.role
        },
        file: {
            id: fileId,
            status: cached.status,
            ownerId: cached.ownerId
        }
    });

    if (!opaAllow) {
        logAudit(
            officerId,
            "OPA_DECISION_DENY",
            `OPA/Rego deny ${action} - fileStatus=${cached.status}`
        );

        return res.status(403).json({
            status: "FAILED",
            message: "Hồ sơ phải được duyệt trước khi ký."
        });
    }

    return res.json({
        status: "OK",
        message: "Policy allow"
    });
});

app.post('/api/officer-remote-sign', requireDPoP, async (req, res) => {
    const { fileId, officerId, hsmPin } = req.body;

    const officer = users[officerId];
    if (!officer || officer.role !== "OFFICER") {
        return res.status(403).json({
            status: "FAILED",
            message: "Chỉ cán bộ có thẩm quyền mới được ký hồ sơ!"
        });
    }

    const cached = pdfCache[fileId];
    if (!cached) {
        return res.status(404).json({
            status: "FAILED",
            message: "Không tìm thấy hồ sơ!"
        });
    }

        const opaAllow = await callOPA({
        action: "officer_remote_sign",
        user: {
            id: officerId,
            role: officer.role
        },
        file: {
            id: fileId,
            status: cached.status,
            ownerId: cached.ownerId
        }
    });

    logAudit(
        officerId,
        opaAllow ? "OPA_DECISION_ALLOW" : "OPA_DECISION_DENY",
        opaAllow
            ? "OPA/Rego allow officer_remote_sign"
            : "OPA/Rego deny officer_remote_sign"
    );

    if (!opaAllow) {
        return res.status(403).json({
            status: "FAILED",
            message: "OPA/Rego Blocked: Không đủ quyền hoặc hồ sơ chưa APPROVED!"
        });
    }

    try {
        const documentHash = crypto.createHash('sha256').update(cached.buffer).digest('hex');

        revokeOldSignatures(documentHash, "REMOTE");

        const signatureBase64 = hsmSignPKCS11(documentHash, hsmPin || "123456");

        signatureRegistry[fileId] = {
            signatureId: Date.now().toString(),
            userId: officerId,
            timestamp: new Date().toISOString(),
            signature: signatureBase64,
            fileHash: documentHash,
            revoked: false,
            type: "REMOTE",
            signerCertPath: officer.remoteCrtPath
        };

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
            execSync(`python3 "${pythonScript}" "${tempPdfPath}" "${finalPdfPath}" "${hsmP12Path}" "${hsmP12Pin}"`, {
                cwd: path.join(__dirname, '../../tsp/python_core'),
                stdio: 'inherit'
            });

            if (fs.existsSync(tempPdfPath)) fs.unlinkSync(tempPdfPath);
        } catch (e) {
            console.error(`[PYTHON ERROR] Lỗi khi ký HSM Officer: ${e.message}`);
            if (fs.existsSync(tempPdfPath)) fs.renameSync(tempPdfPath, finalPdfPath);
        }

        saveRegistry();

        const downloadUrlSig = generateDetachedSignatureFile(signedFileName, signatureBase64);

        cached.status = "SIGNED";
        cached.signedBy = officerId;
        cached.signType = "REMOTE";
        cached.downloadUrl = `/download-signed/${signedFileName}`;
        cached.downloadUrlSig = downloadUrlSig;

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
        res.status(500).json({
            status: "FAILED",
            message: "Lỗi ký HSM: " + e.message
        });
    }
});

app.post('/api/verify-signature', async (req, res) => {
    const { documentHash, signatureBase64, certificatePEM, fileId } = req.body;
    console.log("=== DATA TỪ AGENT GỬI LÊN ===");
    console.log("Hash:", documentHash);
    console.log("FileId:", fileId);
    console.log("Signature (50 chars):", signatureBase64 ? signatureBase64.substring(0, 50) : "MISSING");
    console.log("Cert PEM (50 chars):", certificatePEM ? certificatePEM.substring(0, 50) : "MISSING");
    try {
        const cert = forge.pki.certificateFromPem(certificatePEM);
        const cn = cert.subject.getField('CN').value;
        const matchedUserId = Object.keys(users)
            .sort((a, b) => b.length - a.length)
            .find(id => cn.startsWith(id + '_'));

        if (!matchedUserId) {
            return res.json({ status: 'FAILED', message: "Không xác định được chủ thể chứng chỉ!" });
        }

        const userId = matchedUserId;
        const userName = cn.substring(userId.length + 1);
        const signerUser = users[userId];

        if (!signerUser || signerUser.role !== "OFFICER") {
            return res.json({ status: 'FAILED', message: "Chỉ cán bộ có thẩm quyền mới được ký hồ sơ!" });
        }

        if (getRevokedList().find(i => i.userId === userId)) return res.json({ status: 'FAILED', message: "Chứng chỉ đã bị thu hồi!" });
        const cached = pdfCache[fileId];
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
            revokeOldSignatures(documentHash, "LOCAL");

            signatureRegistry[fileId] = {
            signatureId: Date.now().toString(),
            userId,
            timestamp: new Date().toISOString(),
            signature: signatureBase64,
            fileHash: documentHash,
            revoked: false,
            type: "LOCAL",
            certificatePEM: certificatePEM,
            signerCertPath: users[userId]?.p12Path
                ? path.join(KEYSTORE_DIR, `citizen_${userId}.crt`)
                : null
        };

            const host = req.headers.host || 'localhost:3000';
            const signedPdfBuffer = await embedSignatureAndSeal(cached.buffer, userName, userId, fileId, signatureBase64, "LOCAL", host);
            const signedFileName = `LocalSigned_${Date.now()}.pdf`;

            const tempPdfPath = path.join(SIGNED_DIR, `temp_${signedFileName}`);
            const finalPdfPath = path.join(SIGNED_DIR, signedFileName);
            fs.writeFileSync(tempPdfPath, signedPdfBuffer);
            try {
                const pythonScript = path.join(__dirname, '../../tsp/python_core/sign_pdf.py');
                // Dùng chứng chỉ thực tế của người dùng nếu có
                const userP12Path = users[userId]?.p12Path && fs.existsSync(users[userId].p12Path)
                    ? users[userId].p12Path
                    : path.join(__dirname, '../../tsp/python_core/test_cert.p12');
                const userPin = users[userId]?.certPin || 'secret';
                
                console.log(`[PYTHON] Đang gọi lệnh ký Local cho: ${signedFileName} bằng cert của ${userId}`);
                execSync(`python3 "${pythonScript}" "${tempPdfPath}" "${finalPdfPath}" "${userP12Path}" "${userPin}"`, { 
                    cwd: path.join(__dirname, '../../tsp/python_core'),
                    stdio: 'inherit'
                });

                if (fs.existsSync(tempPdfPath)) fs.unlinkSync(tempPdfPath);
            } catch(e) {
                console.error(`[PYTHON ERROR] Lỗi khi ký Local: ${e.message}`);
                if (fs.existsSync(tempPdfPath)) fs.renameSync(tempPdfPath, finalPdfPath);
            }
            saveRegistry();

            const downloadUrlSig = generateDetachedSignatureFile(signedFileName, signatureBase64);

            cached.status = "SIGNED";
            cached.signedBy = userId;
            cached.signType = "LOCAL";
            cached.downloadUrl = `/download-signed/${signedFileName}`;
            cached.downloadUrlSig = downloadUrlSig;

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
        } else res.json({ status: 'FAILED', message: "Chữ ký giả mạo!" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

async function verifyPdfPath(pdfPath, originalName) {
    let pythonOut = "";
    try {
        const pythonScript = path.join(__dirname, '../../tsp/python_core/verify_pdf.py');
        pythonOut = execSync(`python3 "${pythonScript}" "${pdfPath}" 2>&1`).toString();
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

        if (fileIdForRegistry && signatureRegistry[fileIdForRegistry]?.revoked) {
            saveLTVArchive({
                verify_time: new Date().toISOString(),
                document: originalName || "uploaded.pdf",
                signer: "UNKNOWN",
                timestamp_valid: pythonOut.includes("Timestamp valid: True"),
                ocsp_status: "REVOKED",
                verification_result: "REVOKED",
                certificate_path: signatureRegistry[fileIdForRegistry]?.signerCertPath || "N/A",
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

        const sig = signatureRegistry[fileIdForRegistry];
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
                return {
                    valid: false,
                    message: "Không kiểm tra được OCSP responder!"
                };
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

        return { 
            valid: true, 
            signer: signerName,
            message: formatted
        };
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

    const sig = signatureRegistry[fileId];
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
                    isValidSignature = crypto.verify(
                        null,
                        digest,
                        publicKeyPem,
                        Buffer.from(sig.signature, 'base64')
                    );
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
                    isValidSignature = crypto.verify(
                        null,
                        digest,
                        cleanCertPem,
                        Buffer.from(sig.signature, 'base64')
                    );
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

    return {
        valid: true,
        message: `✔️ Tài liệu hợp lệ (Phương thức: ${signType})\nKhông bị thu hồi và toàn vẹn dữ liệu.`,
        signer: `${users[userId]?.name || "Unknown"} (${userId})`
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
        const cached = pdfCache[fileId];
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
app.get('/download-cert/:userId', (req, res) => {
    res.setHeader('Content-Type', 'application/x-pkcs12');
    res.download(users[req.params.userId].p12Path);
});
app.get('/download-signed/:name', (req, res) => res.download(path.join(SIGNED_DIR, req.params.name)));

// ==========================================
// 6. GIAO DIỆN NGƯỜI DÙNG (FRONTEND)
// ==========================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));
// ==========================================
// API CHO CÁN BỘ (OFFICER)
// ==========================================
app.get('/api/pending-requests', (req, res) => {
    const pending = Object.entries(pdfCache)
        .filter(([id, file]) => file.status === "PENDING" || file.status === "APPROVED" || file.status === "SIGNED")
        .map(([id, file]) => ({
            fileId: id,
            hoTen: file.hoTen || 'N/A',
            cccd: file.cccd || 'N/A',
            noiThuongTru: file.noiThuongTru || 'N/A',
            ngayGui: file.ngayGui || 'N/A',
            status: file.status || 'PENDING',
            hash: file.hash || crypto.createHash('sha256').update(file.buffer).digest('hex'),
            downloadUrl: file.downloadUrl || '',
            downloadUrlSig: file.downloadUrlSig || ''
        }));
    res.json(pending);
});

app.get('/api/file-info/:fileId', (req, res) => {
    const file = pdfCache[req.params.fileId];
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
        hash: file.hash || crypto.createHash('sha256').update(file.buffer).digest('hex'),
        downloadUrl: file.downloadUrl || '',
        downloadUrlSig: file.downloadUrlSig || ''
    });
});

app.get('/api/citizen-lookup/:cccd', (req, res) => {
    const cccd = req.params.cccd;

    const citizen = users[cccd];

    if (citizen && citizen.role === "Citizen") {
        return res.json({
            hoTen: citizen.hoTen,
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

app.post('/api/approve', (req, res) => {
    const { fileId, officerId } = req.body;
    const officer = users[officerId];
    if (!officer || officer.role !== "OFFICER") {
        return res.status(403).json({ status: "FAILED", message: "Chỉ cán bộ mới có quyền phê duyệt!" });
    }
    const file = pdfCache[fileId];
    if (!file) return res.status(404).json({ status: "FAILED", message: "Không tìm thấy hồ sơ!" });
    file.status = "APPROVED";
    file.approvedBy = officerId;
    file.approvedAt = new Date().toISOString();
    logAudit(officerId, "APPROVE", `Đã duyệt hồ sơ ${fileId}`);
    res.json({ status: "OK", message: "Đã phê duyệt hồ sơ!" });
});

app.post('/api/reject', (req, res) => {
    const { fileId, officerId, reason } = req.body;
    const officer = users[officerId];
    if (!officer || officer.role !== "OFFICER") {
        return res.status(403).json({ status: "FAILED", message: "Chỉ cán bộ mới có quyền từ chối!" });
    }
    const file = pdfCache[fileId];
    if (!file) return res.status(404).json({ status: "FAILED", message: "Không tìm thấy hồ sơ!" });
    file.status = "REJECTED";
    file.rejectedBy = officerId;
    file.rejectReason = reason || "Thông tin không hợp lệ";
    file.rejectedAt = new Date().toISOString();
    logAudit(officerId, "REJECT", `Từ chối hồ sơ ${fileId}: ${reason}`);
    res.json({ status: "OK", message: "Đã từ chối hồ sơ!" });
});

// ==========================================
// TSA GIẢ LẬP (RFC 3161)
// ==========================================
/*app.post('/api/timestamp', (req, res) => {
    const { documentHash } = req.body;
    const timestamp = new Date().toISOString();
    const timestampToken = {
        version: 1,
        policy: "1.3.6.1.4.1.99999.1",
        messageImprint: { hashAlgorithm: "SHA-256", hashValue: documentHash },
        serialNumber: Date.now(),
        genTime: timestamp,
        tsaName: "Mock TSA - NT219 Project"
    };
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(JSON.stringify(timestampToken));
    const signature = sign.sign(fs.readFileSync(path.join(CA_DIR, 'subCA.key'), 'utf8'), 'base64');
    res.json({ timestampToken, signature, timestamp });
});*/

// ==========================================
// API PHÂN PHỐI PUBLIC KEY
// ==========================================
app.get('/api/public-key/:userId', (req, res) => {
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
// [BỔ SUNG] API lấy danh sách hồ sơ của tôi
app.get('/api/my-requests/:userId', (req, res) => {
    const userId = req.params.userId;
    // Lọc trong bộ nhớ cache những file thuộc về người dùng đang đăng nhập
    const myRequests = Object.entries(pdfCache)
        .filter(([id, file]) => file.ownerId === userId)
        .map(([id, file]) => ({
            fileId: id,
            fileName: file.name,
            hash: file.hash, // Trả về hash để client gửi lại khi gọi lệnh ký
            status: file.status || 'PENDING',
            rejectReason: file.rejectReason || '',
            downloadUrl: file.downloadUrl || '',
            downloadUrlSig: file.downloadUrlSig || ''
        }));
    res.json(myRequests);
});

// ==========================================
// API TẠO PDF TỪ FORM CT07
// ==========================================
app.post('/api/create-ct07', async (req, res) => {
    const { userId, mucDich, email, phone, ghiChu } = req.body;
    const citizen = users[userId];

    if (!citizen || citizen.role !== "Citizen") {
        return res.status(403).json({
            status: "FAILED",
            message: "Tài khoản công dân không hợp lệ!"
        });
    }

    const hoTen = citizen.hoTen || citizen.name;
    const cccd = citizen.cccd || userId;
    const ngaySinh = citizen.ngaySinh || "";
    const gioiTinh = citizen.gioiTinh || "";
    const noiThuongTru = citizen.noiThuongTru || "";

    try {
        const pdfDoc = await PDFDocument.create();
        const page = pdfDoc.addPage([595, 842]);
        const { width, height } = page.getSize();

        // Dùng font Helvetica (không dấu)
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

        // Tiêu đề - Không dấu để tránh lỗi encode
        page.drawText('CONG HOA XA HOI CHU NGHIA VIET NAM', {
            x: 50, y: height - 50, size: 14, font: fontBold
        });
        page.drawText('Doc lap - Tu do - Hanh phuc', {
            x: 50, y: height - 70, size: 12, font: fontBold
        });

        page.drawText('GIAY XAC NHAN THONG TIN VE CU TRU', {
            x: 50, y: height - 120, size: 16, font: fontBold
        });
        page.drawText('(Cap tu he thong dich vu cong)', {
            x: 50, y: height - 140, size: 11, font: font
        });

        const boDau = (str) => str.normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D');

        const lines = [
            `Ho va ten: ${boDau(hoTen)}`,
            `So CCCD/CMND: ${boDau(cccd)}`,
            `Ngay sinh: ${formatDateVN(ngaySinh)}`,
            `Gioi tinh: ${boDau(gioiTinh)}`,
            `Noi thuong tru: ${boDau(noiThuongTru)}`,
            `Muc dich xin cap: ${boDau(mucDich)}`,
            '',
            'Xac nhan cua Co quan Cong an phuong...',
            '',
            '',
            'Nguoi xac nhan',
            '(Ky, ghi ro ho ten)'
        ];

        let yPos = height - 180;
        for (const line of lines) {
            page.drawText(line, {
                x: 50, y: yPos, size: 12, font: font
            });
            yPos -= 25;
        }

        const pdfBuffer = Buffer.from(await pdfDoc.save());
        const fileId = Date.now().toString();
        const hash = crypto.createHash('sha256').update(pdfBuffer).digest('hex');

        pdfCache[fileId] = {
            buffer: pdfBuffer,
            name: `XacNhanCuTru_${cccd.replace(/\s/g, '')}.pdf`,
            hash: hash,
            ownerId: userId,
            status: "PENDING",
            hoTen: hoTen || '',
            cccd: cccd || '',
            noiThuongTru: noiThuongTru || '',
            ngaySinh: ngaySinh || '',
            gioiTinh: gioiTinh || '',
            mucDich: mucDich || '',
            email: email || citizen.email || '',
            phone: phone || citizen.phone || '',
            ghiChu: ghiChu || '',
            ngayGui: nowVN()
        };

        logAudit(userId, "CREATE_RESIDENCE_REQUEST", `Tao ho so xac nhan cu tru cho ${hoTen}`);
        res.json({
            fileId,
            fileName: `XacNhanCuTru_${cccd.replace(/\s/g, '')}.pdf`,
            hash: hash
        });

    } catch (e) {
        console.error("Loi tao PDF:", e);
        res.status(500).json({ status: "FAILED", message: "Loi tao file PDF!" });
    }
});

// ==========================================
// 1. TSA GIẢ LẬP (MOCK TIMESTAMPING AUTHORITY - RFC 3161)
// ==========================================
/*app.post('/api/timestamp', (req, res) => {
    const { documentHash } = req.body;
    
    if (!documentHash) {
        return res.status(400).json({ 
            status: "REJECTED", 
            error: "Thiếu thông tin documentHash để đóng dấu thời gian!" 
        });
    }

    const currentTime = new Date().toISOString();
    
    // Giả lập TSA Server ký số lên gói tin thời gian bằng thuật toán HMAC-SHA256
    const tsaSignatureToken = crypto
        .createHmac('sha256', 'SECRET_TSA_PRIVATE_KEY_NT219')
        .update(`${documentHash}|${currentTime}`)
        .digest('hex');

    // Phản hồi đúng cấu trúc đặc tả dịch vụ cấp dấu thời gian
    res.json({
        status: "GRANTED",
        policy: "1.3.6.1.4.1.4146.2.2", // OID giả lập của TSA
        timestamp: currentTime,
        serialNumber: Date.now().toString(),
        tsaToken: tsaSignatureToken,
        hashAlgorithm: "SHA-256"
    });
});*/

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

const server = serverOptions.key 
    ? https.createServer(serverOptions, app) 
    : app;

server.listen(port, () => {
    const protocol = serverOptions.key ? 'https' : 'http';
    console.log(`🚀 Server chạy thành công tại: ${protocol}://localhost:${port}`);
});