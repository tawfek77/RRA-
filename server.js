const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

const DB_PATH = path.join(__dirname, 'database.json');
const HTML_PATH = path.join(__dirname, 'mzwtkj6.html');

// Initialize database
let db = {
    keys: {
        '7RZ-VIP': { type: 'lifetime', createdAt: Date.now(), boundIP: null },
        'NULLNEXT-2026': { type: 'lifetime', createdAt: Date.now(), boundIP: null },
        'TRIGGER-PRO': { type: 'lifetime', createdAt: Date.now(), boundIP: null }
    },
    logs: [], // { ip, action, date }
    admins: { '7rz': '7rzRRA@@!!' }
};

if (fs.existsSync(DB_PATH)) {
    try {
        db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    } catch(e) {
        console.error('Failed to parse database.json, starting fresh.');
    }
}

if (!db.admins) {
    db.admins = { '7rz': '7rzRRA@@!!' };
    saveDB();
}

function saveDB() {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function logVisitor(req, action) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    db.logs.push({
        ip: ip,
        action: action,
        date: new Date().toISOString()
    });
    // Keep last 100 logs
    if (db.logs.length > 100) db.logs.shift();
    saveDB();
    return ip;
}

// Serve the HTML file
app.get('/', (req, res) => {
    logVisitor(req, 'Page View');
    res.sendFile(HTML_PATH);
});

// Verify Key API
app.post('/api/verify', (req, res) => {
    const { key } = req.body;
    const ip = logVisitor(req, `Attempt verify: ${key}`);
    
    if (!key || !db.keys[key]) {
        return res.status(401).json({ success: false, message: 'Invalid Key' });
    }

    const keyData = db.keys[key];
    
    // Check Expiration
    if (keyData.type !== 'lifetime') {
        let durationMs = 0;
        if (keyData.type === '1h') durationMs = 60 * 60 * 1000;
        else if (keyData.type === '1d') durationMs = 24 * 60 * 60 * 1000;
        else if (keyData.type === '30d') durationMs = 30 * 24 * 60 * 60 * 1000;
        else if (keyData.type === '60d') durationMs = 60 * 24 * 60 * 60 * 1000;
        
        if (Date.now() - keyData.createdAt > durationMs) {
            return res.status(401).json({ success: false, message: 'Key Expired' });
        }
    }

    // Check IP Binding
    if (keyData.boundIP && keyData.boundIP !== ip) {
        return res.status(401).json({ success: false, message: 'Key bound to another device' });
    }

    // Bind IP if not bound
    if (!keyData.boundIP) {
        keyData.boundIP = ip;
        saveDB();
    }

    res.json({ success: true, message: 'Access Granted' });
});


// Check Session API
app.get('/api/session', (req, res) => {
    const key = req.query.key;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!key || !db.keys[key]) {
        return res.json({ valid: false });
    }

    const keyData = db.keys[key];
    
    // Check Expiration
    if (keyData.type !== 'lifetime') {
        let durationMs = 0;
        if (keyData.type === '1h') durationMs = 60 * 60 * 1000;
        else if (keyData.type === '1d') durationMs = 24 * 60 * 60 * 1000;
        else if (keyData.type === '30d') durationMs = 30 * 24 * 60 * 60 * 1000;
        else if (keyData.type === '60d') durationMs = 60 * 24 * 60 * 60 * 1000;
        
        if (Date.now() - keyData.createdAt > durationMs) {
            return res.json({ valid: false });
        }
    }

    // Check IP
    if (keyData.boundIP && keyData.boundIP !== ip) {
        return res.json({ valid: false });
    }

    res.json({ valid: true });
});

// Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    logVisitor(req, 'Admin Login Attempt');
    if (db.admins && db.admins[username] === password) {
        res.json({ success: true, token: 'admin_secret_token_123' });
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized' });
    }
});

// Admin Middleware
function adminAuth(req, res, next) {
    const token = req.headers['authorization'];
    if (token === 'admin_secret_token_123') next();
    else res.status(401).json({ success: false, message: 'Unauthorized' });
}

// Admin: Get Data
app.get('/api/admin/data', adminAuth, (req, res) => {
    res.json(db);
});

// Admin: Generate Key
app.post('/api/admin/generate', adminAuth, (req, res) => {
    const { duration } = req.body; // '1h', '1d', '30d', '60d', 'lifetime'
    const newKey = '7RZ-' + uuidv4().substring(0, 8).toUpperCase() + '-' + uuidv4().substring(0, 4).toUpperCase();
    
    db.keys[newKey] = {
        type: duration,
        createdAt: Date.now(),
        boundIP: null
    };
    saveDB();
    res.json({ success: true, key: newKey });
});

// Admin: Reset Key (Unbind IP)
app.post('/api/admin/reset', adminAuth, (req, res) => {
    const { key } = req.body;
    if (db.keys[key]) {
        db.keys[key].boundIP = null;
        saveDB();
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: 'Key not found' });
    }
});

// Admin: Delete Key
app.post('/api/admin/delete', adminAuth, (req, res) => {
    const { key } = req.body;
    if (db.keys[key]) {
        delete db.keys[key];
        saveDB();
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: 'Key not found' });
    }
});


// Admin: Add User
app.post('/api/admin/users/add', adminAuth, (req, res) => {
    if (String(req.headers['x-admin-user']).trim() !== '7rz') return res.status(403).json({ success: false, message: 'Only the primary admin (7rz) can do this. Header received: ' + req.headers['x-admin-user'] });
    
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Missing fields' });
    if (db.admins[username]) return res.json({ success: false, message: 'User already exists' });
    
    db.admins[username] = password;
    saveDB();
    res.json({ success: true });
});

// Admin: Delete User
app.post('/api/admin/users/delete', adminAuth, (req, res) => {
    if (String(req.headers['x-admin-user']).trim() !== '7rz') return res.status(403).json({ success: false, message: 'Only the primary admin (7rz) can do this. Header received: ' + req.headers['x-admin-user'] });

    const { username } = req.body;
    if (username === '7rz') return res.json({ success: false, message: 'Cannot delete primary admin' });
    
    if (db.admins[username]) {
        delete db.admins[username];
        saveDB();
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'User not found' });
    }
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
});
