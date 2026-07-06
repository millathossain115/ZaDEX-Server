require('dotenv').config();

const app = require('./src/app');
const { connectDB } = require('./src/config/db');

const port = process.env.PORT || 5000;

app.listen(port, async () => {
    console.log(`\n🚀 Server is listening on port \x1b[36m${port}\x1b[0m`);
    try {
        await connectDB();
    } catch (err) {
        console.error('❌ MongoDB connection failed:', err.message);
    }
});

module.exports = app;