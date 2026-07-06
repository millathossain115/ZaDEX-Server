const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { connectDB, userCollection } = require('../config/db');
const { verifyToken, verifyAdmin } = require('../middleware/auth');

// GET /users/role — Get role of logged-in user
router.get('/role', verifyToken, async (req, res) => {
    await connectDB();
    const email = req.query.email;
    if (!email) return res.status(400).send({ message: 'Email is required' });
    if (email.toLowerCase() !== req.decoded.email.toLowerCase()) {
        return res.status(403).send({ message: 'Forbidden: email mismatch' });
    }
    const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const role = user?.role || 'user';
    const status = user?.status || 'active';
    console.log(`🔍 Role check → ${email}: ${role}, status: ${status}`);
    res.send({ role, status });
});

// GET /users/profile — Fetch user profile
router.get('/profile', async (req, res) => {
    await connectDB();
    const email = req.query.email;
    if (!email) return res.status(400).send({ message: 'Email is required' });
    const user = await userCollection.findOne({ email });
    res.send(user || {});
});

// PUT /users/profile — Update user profile
router.put('/profile', async (req, res) => {
    await connectDB();
    try {
        const profileData = req.body;
        const { email, ...updates } = profileData;
        if (!email) return res.status(400).send({ message: 'Email is required' });
        const filter = { email };
        const updateDoc = { $set: updates };
        const result = await userCollection.updateOne(filter, updateDoc, { upsert: true });
        res.send(result);
    } catch (error) {
        console.error('Error in /users/profile:', error);
        res.status(500).send({ message: 'Internal Server Error' });
    }
});

// GET /users — All users (Admin only)
router.get('/', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const result = await userCollection.find().toArray();
    res.send(result);
});

// POST /users — Register a new user
router.post('/', async (req, res) => {
    await connectDB();
    const user = req.body;
    console.log('\n========================================================');
    console.log('🔥 IMPORTANT & NECESSARY INFO: NEW USER REGISTRATION 🔥');
    console.log('========================================================');
    console.log(`👤 Name: ${user.name}`);
    console.log(`📧 Email: ${user.email}`);
    console.log(`🎭 Role: ${user.role?.toUpperCase() || 'USER'}`);
    console.log(`🛡️  Status: ${user.status || 'verified'}`);
    if (user.role === 'rider') console.log('⚠️  ACTION REQUIRED: Rider needs admin approval!');
    console.log('========================================================\n');
    const existingUser = await userCollection.findOne({ email: user.email });
    if (existingUser) return res.send({ message: 'user already exists', insertedId: null });
    const result = await userCollection.insertOne(user);
    res.send(result);
});

// PATCH /users/admin-setup — Bootstrap first admin via secret
router.patch('/admin-setup', async (req, res) => {
    await connectDB();
    const { email, secret } = req.body;
    if (!secret || secret !== process.env.ADMIN_SETUP_SECRET) {
        return res.status(403).send({ message: 'Forbidden: Invalid Admin Setup Secret' });
    }
    const filter = { email };
    const updateDoc = { $set: { role: 'admin' } };
    const result = await userCollection.updateOne(filter, updateDoc);
    if (result.matchedCount === 0) {
        return res.status(404).send({ message: 'User not found. Please register this email first.' });
    }
    res.send({ success: true, message: 'Successfully upgraded the user to an admin!', result });
});

// PATCH /users/make-admin/:id — Promote to Admin (Admin only)
router.patch('/make-admin/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = { $set: { role: 'admin', updatedAt: new Date().toISOString() } };
    const result = await userCollection.updateOne(filter, updatedDoc);
    res.send(result);
});

// PATCH /users/make-rider/:id — Promote to Rider by ID (Admin only)
router.patch('/make-rider/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = { $set: { role: 'rider', status: 'active', updatedAt: new Date().toISOString() } };
    const result = await userCollection.updateOne(filter, updatedDoc);
    console.log(`🏍️ User ${id} promoted to rider`);
    res.send(result);
});

// PATCH /users/role/:email — Change user role by email (Admin only)
router.patch('/role/:email', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const email = req.params.email;
    const { role } = req.body;
    console.log(`🔄 Changing role → ${email}: ${role}`);
    const filter = { email };
    const updatedDoc = {
        $set: { role, status: role === 'rider' ? 'active' : undefined, updatedAt: new Date().toISOString() }
    };
    const result = await userCollection.updateOne(filter, updatedDoc);
    res.send(result);
});

// PATCH /users/disable/:id — Disable/Enable user (Admin only)
router.patch('/disable/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const { disabled } = req.body;
    console.log(`🚫 User ${id} disabled: ${disabled}`);
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = { $set: { disabled, updatedAt: new Date().toISOString() } };
    const result = await userCollection.updateOne(filter, updatedDoc);
    res.send(result);
});

// PUT /users/:id — Edit user details (Admin only)
router.put('/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const updates = req.body;
    console.log(`📝 Admin editing user ${id}:`, updates);
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = { $set: { ...updates, updatedAt: new Date().toISOString() } };
    const result = await userCollection.updateOne(filter, updatedDoc);
    res.send(result);
});

// DELETE /users/:id — Remove a user (Admin only)
router.delete('/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    console.log(`🗑️ Admin deleting user ${id}`);
    const filter = { _id: new ObjectId(id) };
    const result = await userCollection.deleteOne(filter);
    res.send(result);
});

module.exports = router;
