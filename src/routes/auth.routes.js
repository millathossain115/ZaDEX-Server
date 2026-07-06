const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { connectDB, userCollection } = require('../config/db');

// POST /jwt — Issue JWT cookie AND return token in body (for cross-domain support)
router.post('/jwt', async (req, res) => {
    await connectDB();
    const userEmail = req.body.email;
    const user = await userCollection.findOne({ email: userEmail });
    const token = jwt.sign(
        { email: user?.email || userEmail, role: user?.role },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '1h' }
    );
    res
        .cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })
        // Also send token in body so frontend can use Authorization header if cookie fails (cross-domain)
        .send({ success: true, token });
});

// POST /logout — Clear JWT cookie
router.post('/logout', async (req, res) => {
    res.clearCookie('token', { maxAge: 0 }).send({ success: true });
});

// POST /login — Validate credentials and return JWT (for non-Firebase login)
router.post('/login', async (req, res) => {
    await connectDB();
    const { email, password } = req.body;
    const user = await userCollection.findOne({ email });
    if (!user) return res.status(401).send({ message: 'Invalid Email' });
    if (!user.password) return res.status(401).send({ message: 'Invalid email or password' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send({ message: 'Invalid Password' });
    const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '1h' }
    );
    res.send({ token, user: { name: user.name, role: user.role } });
});

module.exports = router;
