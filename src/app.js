const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dns = require('dns');

const corsOptions = require('./config/corsOptions');
const routes = require('./routes');

// Fix: Your system DNS can't resolve SRV records. Use Google Public DNS instead.
dns.setDefaultResultOrder('ipv4first');
dns.setServers(['8.8.8.8', '8.8.4.4']);

const app = express();

// --- Middleware ---
app.use((req, res, next) => {
    console.log(`\n🚦 Route Hit: [${req.method}] ${req.url}`);
    next();
});

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// --- Root Route ---
app.get('/', (req, res) => {
    console.log('📱 Frontend/Client just called the / route');
    res.send('ZaDex Server is running...');
});

// --- All Routes ---
app.use(routes);

module.exports = app;
