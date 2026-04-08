const express = require('express');
const cors = require('cors');
require('dotenv').config();
const dns = require('dns');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

// Fix: Your system DNS can't resolve SRV records. Use Google Public DNS instead.
dns.setDefaultResultOrder('ipv4first');
dns.setServers(['8.8.8.8', '8.8.4.4']);

// Create Express app
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use((req, res, next) => {
    console.log(`\n🚦 Route Hit: [${req.method}] ${req.url}`);
    next();
});

app.use(cors({
    origin: [
        'http://localhost:5173',
        'https://zadex-puce.vercel.app',   // old deployment (keep in case)
        'https://zadex-client.vercel.app', // new deployment — update if different
        /^https:\/\/zadex.*\.vercel\.app$/ // allows any zadex-*.vercel.app preview URL
    ],
    credentials: true // Crucial for cookies
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// --- MongoDB Setup (Lazy Connection — Vercel Safe) ---
// The client is created at module load. On Vercel, the driver manages the connection pool.
// We do NOT need to await client.connect() before registering routes.
const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Connect once and cache (Vercel serverless safe pattern)
let isConnected = false;
async function connectDB() {
    if (!isConnected) {
        await client.connect();
        isConnected = true;
        console.log('✅ MongoDB connected (or reused existing connection)');
    }
}

// Get collections (call connectDB first inside each route)
const database = client.db('ZaDexDB');
const parcelCollection = database.collection('parcels');
const userCollection = database.collection('users');
const paymentCollection = database.collection('payments');
const applicationCollection = database.collection('applications');

// --- Middleware: Auth ---

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

// --- Root Route ---
app.get('/', (req, res) => {
    console.log('📱 Frontend/Client just called the / route');
    res.send('ZaDex Server is running...');
});

// --- Auth Routes ---

// POST /jwt — Issue JWT cookie AND return token in body (for cross-domain support)
app.post('/jwt', async (req, res) => {
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
app.post('/logout', async (req, res) => {
    res.clearCookie('token', { maxAge: 0 }).send({ success: true });
});

// POST /login — Validate credentials and return JWT (for non-Firebase login)
app.post('/login', async (req, res) => {
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

// --- Parcel Routes ---

// GET /parcels — Fetch user's own parcels
app.get('/parcels', verifyToken, async (req, res) => {
    await connectDB();
    const email = req.query.email;
    if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'Forbidden access' });
    }
    const result = await parcelCollection.find({ email }).toArray();
    res.send(result);
});

// POST /parcels — Create a new parcel
app.post('/parcels', verifyToken, async (req, res) => {
    await connectDB();
    const parcel = req.body;
    const result = await parcelCollection.insertOne(parcel);
    res.send(result);
});

// GET /parcels/track/:trackingId — Track a parcel (public)
app.get('/parcels/track/:trackingId', async (req, res) => {
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
app.put('/parcels/:id', async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const updateData = req.body;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { ...updateData } };
    const result = await parcelCollection.updateOne(filter, updateDoc);
    res.send(result);
});

// DELETE /parcels/:id — Delete a parcel
app.delete('/parcels/:id', async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const result = await parcelCollection.deleteOne(filter);
    res.send(result);
});

// PUT /parcels/status/:id — Rider updates delivery status
app.put('/parcels/status/:id', verifyToken, verifyRider, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const { status } = req.body;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { status } };
    const result = await parcelCollection.updateOne(filter, updateDoc);
    res.send(result);
});

// PATCH /parcels/:id/cod-collected — Rider marks COD cash collected from receiver
app.patch('/parcels/:id/cod-collected', verifyToken, verifyRider, async (req, res) => {
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
app.patch('/parcels/:id/cod-payment', verifyToken, verifyAdmin, async (req, res) => {
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

// --- Payment Routes ---

// POST /payments — Create a new payment and assign tracking ID
app.post('/payments', async (req, res) => {
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
app.get('/payments', verifyToken, async (req, res) => {
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

// --- Rider Routes ---

// GET /rider/parcels — Fetch assigned parcels for logged-in rider
app.get('/rider/parcels', verifyToken, verifyRider, async (req, res) => {
    await connectDB();
    const email = req.decoded.email;
    const result = await parcelCollection.find({ assignedRider: email }).toArray();
    res.send(result);
});

// --- Admin: Parcel Routes ---

// GET /all-parcels — All parcels with optional search (Admin only)
app.get('/all-parcels', verifyToken, verifyAdmin, async (req, res) => {
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

// --- Rider Applications ---

// POST /rider-applications — Submit a new rider application
app.post('/rider-applications', verifyToken, async (req, res) => {
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
app.get('/rider-applications/my-status', verifyToken, async (req, res) => {
    await connectDB();
    const email = req.decoded.email;
    const application = await applicationCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (!application) return res.send({ hasApplication: false });
    res.send({ hasApplication: true, application });
});

// GET /rider-applications — All applications (Admin only)
app.get('/rider-applications', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const result = await applicationCollection.find().toArray();
    console.log(`📋 Admin fetched ${result.length} rider applications`);
    res.send(result);
});

// PATCH /rider-applications/:id — Approve or Reject application (Admin only)
app.patch('/rider-applications/:id', verifyToken, verifyAdmin, async (req, res) => {
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

// --- User Routes ---

// GET /users/role — Get role of logged-in user
app.get('/users/role', verifyToken, async (req, res) => {
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
app.get('/users/profile', async (req, res) => {
    await connectDB();
    const email = req.query.email;
    if (!email) return res.status(400).send({ message: 'Email is required' });
    const user = await userCollection.findOne({ email });
    res.send(user || {});
});

// PUT /users/profile — Update user profile
app.put('/users/profile', async (req, res) => {
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
app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const result = await userCollection.find().toArray();
    res.send(result);
});

// POST /users — Register a new user
app.post('/users', async (req, res) => {
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
app.patch('/users/admin-setup', async (req, res) => {
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
app.patch('/users/make-admin/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = { $set: { role: 'admin', updatedAt: new Date().toISOString() } };
    const result = await userCollection.updateOne(filter, updatedDoc);
    res.send(result);
});

// PATCH /users/make-rider/:id — Promote to Rider by ID (Admin only)
app.patch('/users/make-rider/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = { $set: { role: 'rider', status: 'active', updatedAt: new Date().toISOString() } };
    const result = await userCollection.updateOne(filter, updatedDoc);
    console.log(`🏍️ User ${id} promoted to rider`);
    res.send(result);
});

// PATCH /users/role/:email — Change user role by email (Admin only)
app.patch('/users/role/:email', verifyToken, verifyAdmin, async (req, res) => {
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
app.patch('/users/disable/:id', verifyToken, verifyAdmin, async (req, res) => {
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
app.put('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
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
app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
    await connectDB();
    const id = req.params.id;
    console.log(`🗑️ Admin deleting user ${id}`);
    const filter = { _id: new ObjectId(id) };
    const result = await userCollection.deleteOne(filter);
    res.send(result);
});

// Start the server (only used locally, Vercel uses module.exports)
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

module.exports = app;