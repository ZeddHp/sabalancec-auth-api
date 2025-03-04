const express = require('express');
const bcrypt = require('bcryptjs'); // PASSWORD HASHING MODULE
const { validatePassword } = require('./utils/validation'); // PASSWORD VALIDATION FUNCTION
const jwt = require('jsonwebtoken'); // JWT MODULE
const { users } = require('./models/userModel'); // USER MODEL
const { userRefreshTokens } = require('./models/refreshTokenModel'); // REFRESH TOKEN MODEL
const { userInvalidTokens } = require('./models/invalidTokenModel'); // INVALID TOKEN MODEL
const config = require('./config/config'); // CONFIGURATION MODULE
const { ensureAuthenticated } = require('./middlewares/authMiddleware'); // AUTHENTICATION MIDDLEWARE
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');


// Initialize express
const app = express();

// Configure body parser
app.use(express.json());


app.get('/', (req, res) => {
    res.send(`Server is running on http://localhost:${config.port} <br>
              Open API documentation on http://localhost:${config.port}/api-docs`);
});

// Load Swagger document
const swaggerDocument = YAML.load('swagger/swagger.yaml');

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));




/**
 * Register a new user
 * @route POST /api/register
 * @access Public
 * @param {Object} req.body - { fullName, email, address, password }
 * @returns {Object} { message, id }
 */
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, address, password } = req.body;

        // check if all fields are provided
        if (!fullName || !email || !address || !password) {
            return res.status(422).json({ error: 'All fields are required (fullName, email, address, password)' });
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
            fullName,
            email,
            address,
            password: hashedPassword
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
 * @returns {Object} { id, fullName, email, address, accessToken }
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
            fullName: user.fullName,
            email: user.email,
            address: user.address,
            accessToken,
            refreshToken
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});




/**
 * refresh access token
 * @route POST /api/refresh-token
 * @access Public
 * @param {String} req.body - { refreshToken }
 * @returns {Object} { accessToken, refreshToken }
 */
app.post('/api/refresh-token', async (req, res) => {
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
 * Log out a user
 * @route POST /api/logout
 * @access Private
 * @param {String} req.headers.authorization - Access Token
 * @returns {Object} 204 - No Content
 */
app.post('/api/logout', ensureAuthenticated, async (req, res) => {
    try {
        const refreshToken = req.body
        await userRefreshTokens.remove({ refreshToken: refreshToken });

        await userRefreshTokens.removeMany({ userId: req.user._id });
        await userRefreshTokens.compactDatafile();

        await userInvalidTokens.insert({
            accessToken: req.accessToken.value,
            userId: req.user._id,
            expirationTime: req.accessToken.exp
        });

        return res.status(204).send();
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});




/**
 * Reset user password
 * @route POST /api/password/reset
 * @access Private
 * @param {String} req.body - { currentPassword, newPassword }
 * @param {String} req.headers.authorization - Access Token
 * @returns {Object} { message || error }
 */
app.post('/api/password/reset', ensureAuthenticated, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(422).json({ error: 'All fields are required (currentPassword, newPassword)' });
        }

        const user = await users.findOne({ _id: req.user._id });

        const passwordMatch = await bcrypt.compare(currentPassword, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        if (!validatePassword(newPassword).valid) {
            return res.status(422).json({ error: validatePassword(newPassword).error })
        };

        const hashedPassword = await bcrypt.hash(newPassword, 12);

        await users.update({ _id: req.user._id }, { $set: { password: hashedPassword } });

        return res.status(200).json({ message: 'Password reset successfully' });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});



/**
 * Get authenticated user details
 * @route GET /api/user
 * @access Private
 * @param {String} req.headers.authorization - Access Token
 * @returns {Object} { id, fullName, email, address }
 */
app.get('/api/user', ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user._id });

        return res.status(200).json({
            id: user._id,
            fullName: user.fullName,
            email: user.email,
            address: user.address
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }

});



/**
 * Update user profile
 * @route PUT /api/user
 * @access Private
 * @param {Object} req.body - { fullName, email, address }
 * @param {String} req.headers.authorization - Access Token
 * @returns {Object} { message }
 */
app.put('/api/user', ensureAuthenticated, async (req, res) => {
    try {
        const { fullName, email, address } = req.body;

        if (!fullName || !email || !address) {
            return res.status(422).json({ error: 'All fields are required (fullName, email, address)' });
        }

        await users.update({ _id: req.user._id }, { $set: { fullName, email, address } });

        //print updated user
        const user = await users.findOne({ _id: req.user._id });

        const userObj = {
            id: user._id,
            fullName: user.fullName,
            email: user.email,
            address: user.address
        };

        return res.status(200).json({ message: 'User profile updated successfully', user: userObj });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.listen(config.port, () => {
    console.log(`Server is running on http://localhost:${config.port}`);
});

