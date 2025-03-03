const express = require('express');
//const Datastore = require('nedb-promises'); // DATABASE MODULE
const bcrypt = require('bcryptjs'); // PASSWORD HASHING MODULE
const { validatePassword } = require('./utils/validation'); // PASSWORD VALIDATION FUNCTION
//const { ensureAuthenticated } = require('./middlewares/authMiddleware'); // AUTHENTICATION MIDDLEWARE
const jwt = require('jsonwebtoken'); // JWT MODULE
const { users, userRefreshTokens } = require('./models/userModel'); // USER MODELS

const config = require('./config/config'); // CONFIGURATION MODULE

// Initialize express
const app = express();
const PORT = 3000;

// Configure body parser
app.use(express.json());


// const users = Datastore.create({ filename: 'Users.db', autoload: true }); // !TODO: swhitch to DBMS

// const userRefreshTokens = Datastore.create({ filename: 'UserRefreshTokens.db', autoload: true }); // !TODO: swhitch to DBMS

// module.exports = { users, userRefreshTokens };

app.get('/', (req, res) => {
    res.send('REST API with Node.js, Express, and MongoDB');
});


/**
 * Register a new user
 * @route POST /api/register
 * @access Public
 * @param {Object} req.body - { name, email, password, role }
 * @returns {Object} { message, id }
 */
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // check if all fields are provided
        if (!name || !email || !password) {
            return res.status(422).json({ error: 'All fields are required (name, email, password)' });
        }

        // email validation for existing user
        if (await users.findOne({ email })) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        // password validation
        if (!validatePassword(password).valid) {
            return res.status(422).json({ error: validatePassword(password).error })
        };

        // wait for password to be hashed
        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = await users.insert({
            name,
            email,
            password: hashedPassword,
            role: role ?? 'user',
        });

        return res.status(201).json({ message: 'User registered successfully', id: newUser._id });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});


/**
 * Log in a user
 * @route POST /api/login
 * @access Public
 * @param {Object} req.body - { email, password }
 * @returns {Object} { id, name, email, accessToken }
 */
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // check if all fields are provided
        if (!email || !password) {
            return res.status(422).json({ error: 'All fields are required (email, password)' });
        }

        const user = await users.findOne({ email });

        // check if user exists
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, { subject: 'Authorization', expiresIn: config.accessTokenExpiresIn });

        const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'Refresh', expiresIn: config.refreshTokenExpiresIn });

        await userRefreshTokens.insert({
            token: refreshToken,
            userId: user._id
        });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken,
            refreshToken
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});


/**
 * refresh access token
 * @route POST /api/refresh
 * @access Public
 * @param {String} req.body - { refreshToken }
 * @returns {Object} { accessToken, refreshToken }
 */
app.post('/api/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({ error: 'Refresh token not found' });
        }

        const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);

        const userRefreshToken = await userRefreshTokens.findOne({ token: refreshToken, userId: decodedRefreshToken.userId });

        if (!userRefreshToken) {
            return res.status(401).json({ error: 'Refresh token not found' });
        }

        await userRefreshTokens.remove({ _id: userRefreshToken._id });
        await userRefreshTokens.compactDatafile();

        const accessToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.accessTokenSecret, { subject: 'Authorization', expiresIn: config.accessTokenExpiresIn });

        const newRefreshToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.refreshTokenSecret, { subject: 'Refresh', expiresIn: config.refreshTokenExpiresIn });

        await userRefreshTokens.insert({
            token: newRefreshToken,
            userId: decodedRefreshToken.userId
        });

        return res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ error: 'Refresh token expired' });
        }

        return res.status(500).json({ error: error.message });
    }
});

/**
 * Get authenticated user details
 * @route GET /api/user
 * @access Private
 * @param {String} req.headers.authorization - Access Token
 * @returns {Object} { id, name, email, prof_pic (nullable) }
 */
app.get('/api/user', ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user._id });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            prof_pic: user.prof_pic || null,
            // varam vēl pēc nepieciešamības
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }

});


// Middleware to verify the access token
async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization;
    if (!accessToken) {
        return res.status(401).json({ error: 'Access token is required' });
    }

    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
        req.user = await users.findOne({ _id: decodedAccessToken.userId });
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Access token invalid or expired' });
    }
}


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

