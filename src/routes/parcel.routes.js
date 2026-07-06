const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { connectDB, parcelCollection } = require('../config/db');
const { verifyToken, verifyRider, verifyAdmin } = require('../middleware/auth');

// GET /parcels — Fetch user's own parcels
router.get('/', verifyToken, async (req, res) => {
    await connectDB();
    const email = req.query.email;
    if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'Forbidden access' });
    }
    const result = await parcelCollection.find({ email }).toArray();
    res.send(result);
});

// POST /parcels — Create a new parcel
router.post('/', verifyToken, async (req, res) => {
    await connectDB();
    const parcel = req.body;
    const result = await parcelCollection.insertOne(parcel);
    res.send(result);
});

// GET /parcels/track/:trackingId — Track a parcel (public)
router.get('/track/:trackingId', async (req, res) => {
    await connectDB();
    const trackingId = req.params.trackingId;
    const isObjectId = ObjectId.isValid(trackingId) && String(new ObjectId(trackingId)) === trackingId;
    const query = {
        $or: [
            { trackingId },
            { transactionId: trackingId },
            ...(isObjectId ? [{ _id: new ObjectId(trackingId) }] : [])
        ]
    };
    const result = await parcelCollection.findOne(query);
    if (!result) return res.status(404).send({ message: 'Parcel not found with this tracking ID' });
    res.send(result);
});

// PUT /parcels/:id — Update a parcel
router.put('/:id', async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const updateData = req.body;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { ...updateData } };
    const result = await parcelCollection.updateOne(filter, updateDoc);
    res.send(result);
});

// DELETE /parcels/:id — Delete a parcel
router.delete('/:id', async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const result = await parcelCollection.deleteOne(filter);
    res.send(result);
});

// PUT /parcels/status/:id — Rider updates delivery status
router.put('/status/:id', verifyToken, verifyRider, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const { status } = req.body;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { status } };
    const result = await parcelCollection.updateOne(filter, updateDoc);
    res.send(result);
});

// PATCH /parcels/:id/cod-collected — Rider marks COD cash collected from receiver
router.patch('/:id/cod-collected', verifyToken, verifyRider, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    console.log(`💰 Rider marking COD collected for parcel ${id}`);
    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
        $set: {
            riderCodStatus: 'collected',
            codCollectedAt: new Date().toISOString(),
        }
    };
    const result = await parcelCollection.updateOne(filter, updateDoc);
    res.send(result);
});

// PATCH /parcels/:id/cod-payment — Admin confirms COD cash received from rider
router.patch('/:id/cod-payment', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    console.log(`✅ Admin confirming COD payment for parcel ${id} by ${req.decoded.email}`);
    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
        $set: {
            paymentStatus: 'paid',
            codSettled: true,
            codSettledAt: new Date().toISOString(),
            codSettledBy: req.decoded.email,
        }
    };
    const result = await parcelCollection.updateOne(filter, updateDoc);
    res.send(result);
});

module.exports = router;

// --- Admin: All Parcels router (mounted separately at /all-parcels) ---
const allParcelsRouter = express.Router();

// GET /all-parcels — All parcels with optional search (Admin only)
allParcelsRouter.get('/', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const search = req.query.search;
    let query = {};
    if (search) {
        query = {
            $or: [
                { senderName: { $regex: search, $options: 'i' } },
                { senderEmail: { $regex: search, $options: 'i' } },
                { receiverPhone: { $regex: search, $options: 'i' } },
                { trackingId: { $regex: search, $options: 'i' } }
            ]
        };
    }
    const result = await parcelCollection.find(query).sort({ _id: -1 }).toArray();
    res.send(result);
});

module.exports.allParcelsRouter = allParcelsRouter;
