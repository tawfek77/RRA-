const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();

// Enable CORS for all origins, headers and methods
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-User']
}));
app.use(express.json());

// MongoDB connection string
let MONGODB_URI = process.env.MONGODB_URI;

// If MONGODB_URI is not in process.env, try to load it from config.json
if (!MONGODB_URI) {
    try {
        const configPath = path.join(__dirname, 'config.json');
        if (fs.existsSync(configPath)) {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            MONGODB_URI = config.MONGODB_URI;
        }
    } catch (e) {
        console.error('Failed to read config.json:', e.message);
    }
}

// Fallback to local MongoDB if still not set
if (!MONGODB_URI) {
    MONGODB_URI = 'mongodb://localhost:27017/triggerfinder';
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

// Mongoose Schemas
const KeySchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true },
    type: { type: String, required: true }, // '1h', '1d', '30d', '60d', 'lifetime'
    createdAt: { type: Date, default: Date.now },
    boundIP: { type: String, default: null },
    boundDeviceId: { type: String, default: null }
});

const LogSchema = new mongoose.Schema({
    ip: { type: String, required: true },
    action: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const Key = mongoose.model('Key', KeySchema);
const Log = mongoose.model('Log', LogSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Initialize default admin user if not exists
async function initDefaultAdmin() {
    try {
        const count = await Admin.countDocuments();
        if (count === 0) {
            const defaultAdmin = new Admin({ username: '7rz', password: '7rzRRA@@!!' });
            await defaultAdmin.save();
            console.log('Default admin 7rz created.');
        }
    } catch (e) {
        console.error('Failed to initialize default admin:', e);
    }
}
initDefaultAdmin();

// Helper to log actions
async function logVisitor(req, action) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    try {
        const newLog = new Log({ ip, action });
        await newLog.save();
        
        // Keep only last 200 logs
        const logCount = await Log.countDocuments();
        if (logCount > 200) {
            const oldest = await Log.findOne().sort({ date: 1 });
            if (oldest) await Log.deleteOne({ _id: oldest._id });
        }
    } catch (e) {
        console.error('Failed to save log:', e);
    }
    return ip;
}

// Serve root message
app.get('/', (req, res) => {
    res.send('Trigger Finder API Server is running...');
});

// Verify Key API
app.post('/api/verify', async (req, res) => {
    const { key, deviceId } = req.body;
    const ip = await logVisitor(req, `Attempt verify: ${key}`);
    
    if (!key) {
        return res.status(401).json({ success: false, message: 'Invalid Key' });
    }

    try {
        const keyData = await Key.findOne({ key });
        if (!keyData) {
            return res.status(401).json({ success: false, message: 'Invalid Key' });
        }

        // Check Expiration
        if (keyData.type !== 'lifetime') {
            let durationMs = 0;
            if (keyData.type === '1h') durationMs = 60 * 60 * 1000;
            else if (keyData.type === '1d') durationMs = 24 * 60 * 60 * 1000;
            else if (keyData.type === '30d') durationMs = 30 * 24 * 60 * 60 * 1000;
            else if (keyData.type === '60d') durationMs = 60 * 24 * 60 * 60 * 1000;
            
            if (Date.now() - new Date(keyData.createdAt).getTime() > durationMs) {
                return res.status(401).json({ success: false, message: 'Key Expired' });
            }
        }

        // Check Device Binding (if provided by client)
        if (deviceId) {
            if (keyData.boundDeviceId && keyData.boundDeviceId !== deviceId) {
                return res.status(401).json({ success: false, message: 'Key bound to another device' });
            }
            if (!keyData.boundDeviceId) {
                keyData.boundDeviceId = deviceId;
                keyData.boundIP = ip;
                await keyData.save();
            }
        } else {
            // Fallback to IP Binding for older clients
            if (keyData.boundIP && keyData.boundIP !== ip) {
                return res.status(401).json({ success: false, message: 'Key bound to another device' });
            }
            if (!keyData.boundIP) {
                keyData.boundIP = ip;
                await keyData.save();
            }
        }

        res.json({ success: true, message: 'Access Granted' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Check Session API
app.get('/api/session', async (req, res) => {
    const key = req.query.key;
    const deviceId = req.query.deviceId;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!key) {
        return res.json({ valid: false });
    }

    try {
        const keyData = await Key.findOne({ key });
        if (!keyData) {
            return res.json({ valid: false });
        }
        
        // Check Expiration
        if (keyData.type !== 'lifetime') {
            let durationMs = 0;
            if (keyData.type === '1h') durationMs = 60 * 60 * 1000;
            else if (keyData.type === '1d') durationMs = 24 * 60 * 60 * 1000;
            else if (keyData.type === '30d') durationMs = 30 * 24 * 60 * 60 * 1000;
            else if (keyData.type === '60d') durationMs = 60 * 24 * 60 * 60 * 1000;
            
            if (Date.now() - new Date(keyData.createdAt).getTime() > durationMs) {
                return res.json({ valid: false });
            }
        }

        // Check Device Binding
        if (deviceId && keyData.boundDeviceId) {
            if (keyData.boundDeviceId !== deviceId) {
                return res.json({ valid: false });
            }
        } else {
            // Fallback to IP check
            if (keyData.boundIP && keyData.boundIP !== ip) {
                return res.json({ valid: false });
            }
        }

        res.json({ valid: true });
    } catch (e) {
        res.json({ valid: false });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    await logVisitor(req, 'Admin Login Attempt');
    try {
        const admin = await Admin.findOne({ username, password });
        if (admin) {
            res.json({ success: true, token: 'admin_secret_token_123' });
        } else {
            res.status(401).json({ success: false, message: 'Unauthorized' });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin Middleware
function adminAuth(req, res, next) {
    const token = req.headers['authorization'];
    if (token === 'admin_secret_token_123') next();
    else res.status(401).json({ success: false, message: 'Unauthorized' });
}

// Admin: Get Data
app.get('/api/admin/data', adminAuth, async (req, res) => {
    try {
        const keysList = await Key.find({});
        const logsList = await Log.find({}).sort({ date: -1 }).limit(100);
        const adminsList = await Admin.find({});

        // Format into the structure the client expects
        const keysObj = {};
        keysList.forEach(k => {
            keysObj[k.key] = {
                type: k.type,
                createdAt: new Date(k.createdAt).getTime(),
                boundIP: k.boundIP
            };
        });

        const adminsObj = {};
        adminsList.forEach(a => {
            adminsObj[a.username] = a.password;
        });

        const logsFormatted = logsList.map(l => ({
            ip: l.ip,
            action: l.action,
            date: l.date.toISOString()
        }));

        res.json({
            keys: keysObj,
            logs: logsFormatted,
            admins: adminsObj
        });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Generate Key
app.post('/api/admin/generate', adminAuth, async (req, res) => {
    const { duration } = req.body; // '1h', '1d', '30d', '60d', 'lifetime'
    const newKey = '7RZ-' + uuidv4().substring(0, 8).toUpperCase() + '-' + uuidv4().substring(0, 4).toUpperCase();
    
    try {
        const keyItem = new Key({
            key: newKey,
            type: duration,
            createdAt: new Date(),
            boundIP: null
        });
        await keyItem.save();
        res.json({ success: true, key: newKey });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Reset Key (Unbind IP & Device ID)
app.post('/api/admin/reset', adminAuth, async (req, res) => {
    const { key } = req.body;
    try {
        const keyItem = await Key.findOne({ key });
        if (keyItem) {
            keyItem.boundIP = null;
            keyItem.boundDeviceId = null;
            await keyItem.save();
            res.json({ success: true });
        } else {
            res.status(404).json({ success: false, message: 'Key not found' });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Delete Key
app.post('/api/admin/delete', adminAuth, async (req, res) => {
    const { key } = req.body;
    try {
        const result = await Key.deleteOne({ key });
        if (result.deletedCount > 0) {
            res.json({ success: true });
        } else {
            res.status(404).json({ success: false, message: 'Key not found' });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Add User
app.post('/api/admin/users/add', adminAuth, async (req, res) => {
    if (String(req.headers['x-admin-user']).trim() !== '7rz') {
        return res.status(403).json({ success: false, message: 'Only the primary admin (7rz) can do this.' });
    }
    
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Missing fields' });
    
    try {
        const exists = await Admin.findOne({ username });
        if (exists) return res.json({ success: false, message: 'User already exists' });
        
        const newAdmin = new Admin({ username, password });
        await newAdmin.save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Delete User
app.post('/api/admin/users/delete', adminAuth, async (req, res) => {
    if (String(req.headers['x-admin-user']).trim() !== '7rz') {
        return res.status(403).json({ success: false, message: 'Only the primary admin (7rz) can do this.' });
    }

    const { username } = req.body;
    if (username === '7rz') return res.json({ success: false, message: 'Cannot delete primary admin' });
    
    try {
        const result = await Admin.deleteOne({ username });
        if (result.deletedCount > 0) {
            res.json({ success: true });
        } else {
            res.json({ success: false, message: 'User not found' });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Central API Server running on port ${PORT}`);
});
