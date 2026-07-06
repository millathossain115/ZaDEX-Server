const jwt = require('jsonwebtoken');
const { connectDB, userCollection } = require('../config/db');

// 1. Verify if the token is valid (Cookie OR Authorization Bearer header)
const verifyToken = (req, res, next) => {
    // Check cookie first, then fall back to Authorization: Bearer <token> header
    let token = req.cookies?.token;
    if (!token) {
        const authHeader = req.headers?.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
    }
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Unauthorized access' });
        }
        req.decoded = decoded;
        next();
    });
};

// 2. Verify if the user is a Rider (case-insensitive email lookup)
const verifyRider = async (req, res, next) => {
    await connectDB();
    const email = req.decoded.email;
    const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const isRider = user?.role === 'rider';
    if (!isRider) {
        console.log(`🚫 verifyRider FAILED for ${email} — role in DB: ${user?.role}`);
        return res.status(403).send({ message: 'Forbidden access: Riders only' });
    }
    next();
};

// 3. Verify if the user is an Admin
const verifyAdmin = async (req, res, next) => {
    await connectDB();
    const email = req.decoded.email;
    const user = await userCollection.findOne({ email });
    if (user?.role !== 'admin') {
        return res.status(403).send({ message: 'Forbidden access: Admins only' });
    }
    next();
};

module.exports = { verifyToken, verifyRider, verifyAdmin };
