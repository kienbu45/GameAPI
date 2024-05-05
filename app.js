const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = 'mongodb://localhost:27017'; // MongoDB connection URI
const DB_NAME = 'gaming_db'; // Database name
const COLLECTION_NAME = 'games'; // Collection name
const JWT_SECRET = 'jwt_secret'; // Secret key for JWT

// Middleware
app.use(express.json());

// Authentication middleware
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Unauthorized');
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Forbidden');
        req.user = user;
        next();
    });
}

// Authorization middleware
function authorizeUser(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
    next();
}

// Function to connect to MongoDB
async function connectToMongoDB() {
    try {
        const client = await MongoClient.connect(MONGODB_URI, { useUnifiedTopology: true });
        console.log('Connected to MongoDB');
        return client.db(DB_NAME).collection(COLLECTION_NAME);
    } catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
}

// Routes
// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const collection = await connectToMongoDB();
    const user = await collection.findOne({ username });

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).send('Invalid username or password');
    }

    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET);
    res.json({ token });
});

// Protected routes
// Get all games
app.get('/api/games', authenticateToken, async (req, res) => {
    const collection = await connectToMongoDB();
    const games = await collection.find().toArray();
    res.json(games);
});

// Admin-only route to create a new game
app.post('/api/games', authenticateToken, authorizeUser, async (req, res) => {
    const collection = await connectToMongoDB();
    const game = {
        title: req.body.title,
        genre: req.body.genre
    };
    const result = await collection.insertOne(game);
    res.json(result.ops[0]);
});

// Update a game
app.put('/api/games/:id', authenticateToken, async (req, res) => {
    const collection = await connectToMongoDB();
    const result = await collection.updateOne(
        { _id: ObjectId(req.params.id) },
        { $set: { title: req.body.title, genre: req.body.genre } }
    );
    if (result.modifiedCount === 0) return res.status(404).send('Game not found');
    res.json(await collection.findOne({ _id: ObjectId(req.params.id) }));
});

// Delete a game
app.delete('/api/games/:id', authenticateToken, async (req, res) => {
    const collection = await connectToMongoDB();
    const result = await collection.deleteOne({ _id: ObjectId(req.params.id) });
    if (result.deletedCount === 0) return res.status(404).send('Game not found');
    res.send('Game deleted');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
