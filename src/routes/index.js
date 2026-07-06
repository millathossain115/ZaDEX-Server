const express = require('express');
const router = express.Router();

const { allParcelsRouter } = require('./parcel.routes');

// Mount all route modules
router.use('/', require('./auth.routes'));
router.use('/parcels', require('./parcel.routes'));
router.use('/all-parcels', allParcelsRouter);
router.use('/payments', require('./payment.routes'));
router.use('/rider', require('./rider.routes'));
router.use('/rider-applications', require('./application.routes'));
router.use('/users', require('./user.routes'));

module.exports = router;
