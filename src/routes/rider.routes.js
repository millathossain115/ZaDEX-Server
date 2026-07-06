const express = require('express');
const router = express.Router();
const { connectDB, parcelCollection } = require('../config/db');
const { verifyToken, verifyRider } = require('../middleware/auth');

// GET /rider/parcels — Fetch assigned parcels for logged-in rider
router.get('/parcels', verifyToken, verifyRider, async (req, res) => {
    await connectDB();
    const email = req.decoded.email;
    const result = await parcelCollection.find({ assignedRider: email }).toArray();
    res.send(result);
});

module.exports = router;
