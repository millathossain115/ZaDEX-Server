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

// Check if the secret is loaded correctly
const secretFromEnv = process.env.ADMIN_SETUP_SECRET;
console.log("Secret from .env:", secretFromEnv);

// Middleware
app.use((req, res, next) => {
    console.log(`\n🚦 Route Hit: [${req.method}] ${req.url}`);
    next();
});

app.use(cors({
    origin: ['http://localhost:5173'], // Your Vite Client URL
    credentials: true // Crucial for cookies
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Connect to MongoDB using the full URI from .env
const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});



// Function to connect to MongoDB and set up API routes
async function run() {
    try {
        // Connect the client to the server
        await client.connect();

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("✅ Successfully connected to MongoDB! Database is ready.");

        // Connect to "ZaDexDB" and the "parcels" collection
        const database = client.db("ZaDexDB");
        const parcelCollection = database.collection("parcels");
        const userCollection = database.collection("users");
        const paymentCollection = database.collection("payments");
        const applicationCollection = database.collection("applications");
        
        // 1. Verify if the token is valid (Generic Auth)
        const verifyToken = (req, res, next) => {
            const token = req.cookies?.token;
            if (!token) {
                return res.status(401).send({ message: 'Unauthorized access' });
            }
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'Unauthorized access' });
                }
                req.decoded = decoded; // Contains email and role from the JWT payload
                next();
            });
        };

        // 2. Verify if the user is a Rider (case-insensitive email lookup)
        const verifyRider = async (req, res, next) => {
            const email = req.decoded.email;
            // Case-insensitive lookup — prevents 403 when email casing differs between JWT and DB
            const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
            const isRider = user?.role === 'rider';
            if (!isRider) {
                console.log(`🚫 verifyRider FAILED for ${email} — role in DB: ${user?.role}`);
                return res.status(403).send({ message: 'Forbidden access: Riders only' });
            }
            next();
        };

        // 3. Verify if the user is an Admin (checks DB — more secure than trusting JWT payload alone)
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await userCollection.findOne(query);
            if (user?.role !== 'admin') {
                return res.status(403).send({ message: 'Forbidden access: Admins only' });
            }
            next();
        };

        // Securely make a user an admin. Hit this endpoint via Postman or your Frontend setup page.
        app.patch('/users/admin-setup', async (req, res) => {
            const { email, secret } = req.body;
            
            // Validate the secret against the one set in your .env
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

        // --- Auth API Routes ---

        // 1. Set the Cookie on Login/JWT request
        app.post('/jwt', async (req, res) => {
            const userEmail = req.body.email;
            
            // Find the user in DB to get their actual role
            const user = await userCollection.findOne({ email: userEmail });
            
            // Create token with role inside payload
            const token = jwt.sign(
                { email: user?.email || userEmail, role: user?.role }, 
                process.env.ACCESS_TOKEN_SECRET, 
                { expiresIn: '1h' }
            );

            res
            .cookie('token', token, {
                httpOnly: true, // Prevents JS access (XSS Protection)
                secure: process.env.NODE_ENV === 'production', // Only over HTTPS in prod
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            })
            .send({ success: true });
        });

        // 2. Clear Cookie on Logout
        app.post('/logout', async (req, res) => {
            res
            .clearCookie('token', { maxAge: 0 })
            .send({ success: true });
        });

        // --- API Routes ---

        // 1. GET parcels for a specific user by email
        app.get('/parcels', verifyToken, async (req, res) => {
            const email = req.query.email;
            
            // Security: Prevent users from seeing other people's parcels
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'Forbidden access' });
            }

            const query = { email: email };
            const result = await parcelCollection.find(query).toArray();
            res.send(result);
        });

        // 2. POST a new parcel (Only logged-in users)
        app.post('/parcels', verifyToken, async (req, res) => {
            const parcel = req.body;
            const result = await parcelCollection.insertOne(parcel);
            res.send(result);
        });

        // 3. POST - Create a new payment
        app.post('/payments', async (req, res) => {
            const payment = req.body;
            
            // Save the payment inside the collection
            const result = await paymentCollection.insertOne(payment);

            // Generate tracking id upon successful payment creation
            const trackingId = "TRACK-" + Math.random().toString(36).substring(2, 10).toUpperCase();

            // Update the given parcel with the new tracking info
            if (payment.parcelId) {
                const filter = { _id: new ObjectId(payment.parcelId) };
                const updateDoc = {
                    $set: {
                        paymentStatus: 'Paid',
                        trackingId: trackingId
                    },
                };
                await parcelCollection.updateOne(filter, updateDoc);
            }

            // Return the result with the generated tracking ID so frontend can use it immediately if needed
            res.send({ ...result, trackingId });
        });

        // 3.1. GET - Track parcel by tracking ID
        app.get('/parcels/track/:trackingId', async (req, res) => {
            const trackingId = req.params.trackingId;
            
            // Validate if the ID is a valid MongoDB ObjectId
            const isObjectId = ObjectId.isValid(trackingId) && String(new ObjectId(trackingId)) === trackingId;

            // Search by Tracking ID (backend generated), Transaction ID (frontend generated ZDX-), or the raw _id
            const query = {
                $or: [
                    { trackingId: trackingId },
                    { transactionId: trackingId },
                    ...(isObjectId ? [{ _id: new ObjectId(trackingId) }] : [])
                ]
            };

            const result = await parcelCollection.findOne(query);
            if (!result) {
                return res.status(404).send({ message: 'Parcel not found with this tracking ID' });
            }
            res.send(result);
        });

        // 4. PUT - Update a parcel dynamically (handles all fields, including paymentData)
        app.put('/parcels/:id', async (req, res) => {
            const id = req.params.id;
            const updateData = req.body;

            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    ...updateData
                },
            };
            
            const result = await parcelCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // 5. DELETE - Delete a parcel
        app.delete('/parcels/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const result = await parcelCollection.deleteOne(filter);
            res.send(result);
        });

        // --- Rider Routes ---

        // GET all parcels for a specific rider
        app.get('/rider/parcels', verifyToken, verifyRider, async (req, res) => {
            const email = req.decoded.email;
            // Fetch parcels assigned to this rider
            const result = await parcelCollection.find({ assignedRider: email }).toArray();
            res.send(result);
        });

        // GET all parcels — Admin only (for admin dashboard overview)
        app.get('/all-parcels', verifyToken, verifyAdmin, async (req, res) => {
            const search = req.query.search; // Get the search term from the URL
            let query = {};

            if (search) {
                query = {
                    $or: [
                        // 'i' makes it case-insensitive (e.g., 'saif' matches 'Saif')
                        { senderName: { $regex: search, $options: 'i' } },
                        { senderEmail: { $regex: search, $options: 'i' } },
                        { receiverPhone: { $regex: search, $options: 'i' } },
                        { trackingId: { $regex: search, $options: 'i' } }
                    ]
                };
            }

            const result = await parcelCollection.find(query).toArray();
            res.send(result);
        });

        // PUT: Update status (Only Riders can update delivery status)
        app.put('/parcels/status/:id', verifyToken, verifyRider, async (req, res) => {
            const id = req.params.id;
            const status = req.body.status;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = { $set: { status: status } };
            const result = await parcelCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // POST: Submit a new rider application (Logged-in users only)
        app.post('/rider-applications', verifyToken, async (req, res) => {
            const applicationData = req.body;
            const email = req.decoded.email; // Source of truth from token

            // 1. Check User Collection for existing role/status (Case-Insensitive)
            const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });

            // Check if user is already a rider
            if (user?.role === 'rider') {
                return res.status(400).send({ message: "You are already registered as a Rider." });
            }
            
            // 2. Check Applications Collection for duplicates (Case-Insensitive)
            const existingApplication = await applicationCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
            if (existingApplication) {
                const status = existingApplication.status || 'pending';
                if (status === 'pending') {
                    return res.status(400).send({ message: 'You have a pending application. Please wait for admin review.' });
                } else if (status === 'rejected') {
                    return res.status(400).send({ message: 'Your previous application was not approved. Contact support for details.' });
                }
                return res.status(400).send({ message: 'An application with this email already exists.' });
            }

            // Save the application
            const result = await applicationCollection.insertOne({
                ...applicationData,
                email, // Ensure it's stored with the authenticated email
                status: 'pending',
                appliedAt: new Date(),
            });

            res.send(result);
        });

        // GET: Check my own rider application status (any logged-in user)
        app.get('/rider-applications/my-status', verifyToken, async (req, res) => {
            const email = req.decoded.email;
            // Case-insensitive lookup
            const application = await applicationCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
            
            if (!application) {
                return res.send({ hasApplication: false });
            }
            res.send({ hasApplication: true, application });
        });

        // --- Admin Routes (User Management) ---

        // GET: All rider applications (Admin only)
        app.get('/rider-applications', verifyToken, verifyAdmin, async (req, res) => {
            const result = await applicationCollection.find().toArray();
            console.log(`📋 Admin fetched ${result.length} rider applications`);
            res.send(result);
        });

        // PATCH: Update rider application status — approve ('active') or reject ('rejected')
        app.patch('/rider-applications/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { status } = req.body;
            console.log(`✏️ Updating rider application ${id} → status: ${status}`);
            const filter = { _id: new ObjectId(id) };
            
            // Get the application to find the user email
            const application = await applicationCollection.findOne(filter);
            if (!application) {
                return res.status(404).send({ message: 'Application not found' });
            }

            const updatedDoc = { $set: { status, reviewedAt: new Date().toISOString() } };
            const result = await applicationCollection.updateOne(filter, updatedDoc);

            // If approved, automatically update the user's role in userCollection
            if (status === 'active') {
                console.log(`🔄 Automatically upgrading ${application.email} to Rider role`);
                await userCollection.updateOne(
                    { email: application.email },
                    { $set: { role: 'rider', status: 'active', updatedAt: new Date().toISOString() } }
                );
            }

            res.send(result);
        });

        // PATCH: Update user role by EMAIL (used when approving a rider application)
        app.patch('/users/role/:email', verifyToken, verifyAdmin, async (req, res) => {
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

        // PATCH: Promote a user to Rider role by ID (Admin only)
        app.patch('/users/make-rider/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: { role: 'rider', status: 'active', updatedAt: new Date().toISOString() },
            };
            const result = await userCollection.updateOne(filter, updatedDoc);
            console.log(`🏍️ User ${id} promoted to rider`);
            res.send(result);
        });

        // 7. GET - Fetch user profile
        app.get('/users/profile', async (req, res) => {
            const email = req.query.email;
            if (!email) return res.status(400).send({ message: 'Email is required' });

            const user = await userCollection.findOne({ email });
            res.send(user || {});
        });

        // 8. PUT - Update user profile
        app.put('/users/profile', async (req, res) => {
            try {
                const profileData = req.body;
                const { email, ...updates } = profileData;
                
                if (!email) return res.status(400).send({ message: 'Email is required' });

                const filter = { email };
                const updateDoc = {
                    $set: updates
                };
                
                // Perform the update or create a new profile with that email 
                // We use upsert: true just in case user wasn't originally created in DB correctly via Register
                const result = await userCollection.updateOne(filter, updateDoc, { upsert: true });
                res.send(result);
            } catch (error) {
                console.error("Error in /users/profile:", error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });

        // PUT: Edit user details (Admin only)
        app.put('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const updates = req.body;
            console.log(`📝 Admin editing user ${id}:`, updates);
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = { $set: { ...updates, updatedAt: new Date().toISOString() } };
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        // PATCH: Toggle disable/enable a user (Admin only)
        app.patch('/users/disable/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { disabled } = req.body;
            console.log(`🚫 User ${id} disabled: ${disabled}`);
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = { $set: { disabled, updatedAt: new Date().toISOString() } };
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        // DELETE: Remove a user (Admin only)
        app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log(`🗑️ Admin deleting user ${id}`);
            const filter = { _id: new ObjectId(id) };
            const result = await userCollection.deleteOne(filter);
            res.send(result);
        });

        // --- User Routes ---

        // GET /users/role — Returns the role of any logged-in user (used by useAdmin hook & login redirect)
        app.get('/users/role', verifyToken, async (req, res) => {
            const email = req.query.email;
            if (!email) return res.status(400).send({ message: 'Email is required' });

            // Security: users can only query their own role (Case-insensitive check)
            if (email.toLowerCase() !== req.decoded.email.toLowerCase()) {
                return res.status(403).send({ message: 'Forbidden: email mismatch' });
            }

            // Case-insensitive lookup in DB
            const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
            const role = user?.role || 'user';
            const status = user?.status || 'active';
            console.log(`🔍 Role check → ${email}: ${role}, status: ${status}`);
            res.send({ role, status });
        });

        // GET /users — All users (Admin only, used by MakeAdmin page)
        app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
            const result = await userCollection.find().toArray();
            res.send(result);
        });

        // PATCH /users/make-admin/:id — Promote a user to Admin (Admin only)
        app.patch('/users/make-admin/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    role: 'admin',
                    updatedAt: new Date().toISOString()
                },
            };
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        //  6. POST - Create a new user
        app.post('/users', async (req, res) => {
            const user = req.body;
            
            console.log("\n========================================================");
            console.log("🔥 IMPORTANT & NECESSARY INFO: NEW USER REGISTRATION 🔥");
            console.log("========================================================");
            console.log(`👤 Name: ${user.name}`);
            console.log(`📧 Email: ${user.email}`);
            console.log(`🎭 Role: ${user.role?.toUpperCase() || 'USER'}`);
            console.log(`🛡️  Status: ${user.status || 'verified'}`);
            if (user.role === 'rider') {
                console.log("⚠️  ACTION REQUIRED: Rider needs admin approval!");
            }
            console.log("========================================================\n");

            // Check if user already exists
            const query = { email: user.email };
            const existingUser = await userCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'user already exists', insertedId: null });
            }

            // Insert user with their chosen role
            const result = await userCollection.insertOne(user);
            res.send(result);
        });

        // POST - Login user (validates credentials + issues JWT)
        app.post('/login', async (req, res) => {
            const { email, password } = req.body;

            // 1. Find user in MongoDB
            const user = await userCollection.findOne({ email });
            if (!user) {
                return res.status(401).send({ message: 'Invalid Email' });
            }

            // 2. Guard: user registered via Firebase/social login has no password
            if (!user.password) {
                return res.status(401).send({ message: 'Invalid email or password' });
            }

            // 3. Compare entered password with stored bcrypt hash
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).send({ message: 'Invalid Password' });
            }

            // 4. Generate JWT with role embedded in the payload
            const token = jwt.sign(
                { email: user.email, role: user.role },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '1h' }
            );

            res.send({ token, user: { name: user.name, role: user.role } });
        });

    } catch (error) {
        console.error("❌ Failed to connect to MongoDB:", error.message);
    }
}
run();

//Sample route to check if server is running
app.get('/', (req, res) => {
    console.log('📱 Frontend/Client just called the / route');
    res.send('ZaDex Server is running...');
});


// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});