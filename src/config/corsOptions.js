const corsOptions = {
    origin: [
        'http://localhost:5173',
        'https://zadex-puce.vercel.app',   // old deployment (keep in case)
        'https://zadex-client.vercel.app', // new deployment — update if different
        /^https:\/\/zadex.*\.vercel\.app$/ // allows any zadex-*.vercel.app preview URL
    ],
    credentials: true // Crucial for cookies
};

module.exports = corsOptions;
