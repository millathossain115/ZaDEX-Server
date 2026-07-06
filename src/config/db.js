const { MongoClient, ServerApiVersion } = require('mongodb');

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
        console.log('🍃 Connected to MongoDB');
    }
}

// Collections
const database = client.db('ZaDexDB');
const parcelCollection = database.collection('parcels');
const userCollection = database.collection('users');
const paymentCollection = database.collection('payments');
const applicationCollection = database.collection('applications');

module.exports = {
    client,
    connectDB,
    parcelCollection,
    userCollection,
    paymentCollection,
    applicationCollection,
};
