const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { connectDB, applicationCollection, userCollection } = require('../config/db');
const { verifyToken, verifyAdmin } = require('../middleware/auth');

// POST /rider-applications — Submit a new rider application
router.post('/', verifyToken, async (req, res) => {
    await connectDB();
    const applicationData = req.body;
    const email = req.decoded.email;
    const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (user?.role === 'rider') {
        return res.status(400).send({ message: 'You are already registered as a Rider.' });
    }
    const existingApplication = await applicationCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (existingApplication) {
        const status = existingApplication.status || 'pending';
        if (status === 'pending') return res.status(400).send({ message: 'You have a pending application. Please wait for admin review.' });
        if (status === 'rejected') return res.status(400).send({ message: 'Your previous application was not approved. Contact support for details.' });
        return res.status(400).send({ message: 'An application with this email already exists.' });
    }
    const result = await applicationCollection.insertOne({
        ...applicationData,
        email,
        status: 'pending',
        appliedAt: new Date(),
    });
    res.send(result);
});

// GET /rider-applications/my-status — Check own application status
router.get('/my-status', verifyToken, async (req, res) => {
    await connectDB();
    const email = req.decoded.email;
    const application = await applicationCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (!application) return res.send({ hasApplication: false });
    res.send({ hasApplication: true, application });
});

// GET /rider-applications — All applications (Admin only)
router.get('/', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const result = await applicationCollection.find().toArray();
    console.log(`📋 Admin fetched ${result.length} rider applications`);
    res.send(result);
});

// PATCH /rider-applications/:id — Approve or Reject application (Admin only)
router.patch('/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const { status } = req.body;
    console.log(`✏️ Updating rider application ${id} → status: ${status}`);
    const filter = { _id: new ObjectId(id) };
    const application = await applicationCollection.findOne(filter);
    if (!application) return res.status(404).send({ message: 'Application not found' });
    const updatedDoc = { $set: { status, reviewedAt: new Date().toISOString() } };
    const result = await applicationCollection.updateOne(filter, updatedDoc);
    if (status === 'active') {
        console.log(`🔄 Automatically upgrading ${application.email} to Rider role`);
        await userCollection.updateOne(
            { email: application.email },
            { $set: { role: 'rider', status: 'active', updatedAt: new Date().toISOString() } }
        );
    }
    res.send(result);
});

module.exports = router;
