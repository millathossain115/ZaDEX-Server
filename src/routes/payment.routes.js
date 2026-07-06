const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { connectDB, paymentCollection, parcelCollection } = require('../config/db');
const { verifyToken } = require('../middleware/auth');

// POST /payments — Create a new payment and assign tracking ID
router.post('/', async (req, res) => {
    await connectDB();
    const payment = req.body;
    const result = await paymentCollection.insertOne(payment);
    const trackingId = 'TRACK-' + Math.random().toString(36).substring(2, 10).toUpperCase();
    if (payment.parcelId) {
        const filter = { _id: new ObjectId(payment.parcelId) };
        const updateDoc = { $set: { paymentStatus: 'Paid', trackingId } };
        await parcelCollection.updateOne(filter, updateDoc);
    }
    res.send({ ...result, trackingId });
});

// GET /payments — Fetch payments (by email if provided, admin can fetch all)
router.get('/', verifyToken, async (req, res) => {
    await connectDB();
    const email = req.query.email;

    // If an email is explicitly provided, verify the user is only requesting their own
    if (email) {
        if (email !== req.decoded.email) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        const result = await paymentCollection.find({ email }).sort({ _id: -1 }).toArray();
        return res.send(result);
    }

    // If no email is provided, return all payments (You might want to restrict this to verifyAdmin in the future)
    const result = await paymentCollection.find().sort({ _id: -1 }).toArray();
    res.send(result);
});

module.exports = router;
