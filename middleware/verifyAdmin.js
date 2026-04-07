/**
 * NOTE: The active verifyAdmin middleware is defined INLINE inside index.js
 * (inside the run() function), alongside verifyToken and verifyRider.
 * 
 * This is required because it needs access to `userCollection`, which is
 * only available after the MongoDB connection is established inside run().
 * 
 * The implementation does a live database lookup to verify the admin role,
 * which is more secure than trusting the JWT payload alone.
 * 
 * Usage in routes:
 *   app.get('/admin/route', verifyToken, verifyAdmin, async (req, res) => { ... });
 */
