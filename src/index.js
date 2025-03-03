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
const swaggerJSDoc = require('swagger-jsdoc');


// Initialize express
const app = express();

// Configure body parser
app.use(express.json());


app.get('/', (req, res) => {
    res.send(`Server is running on http://localhost:${config.port}`);
});

const swaggerOptions = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'Authentication API',
            version: '1.0.0',
            description: 'This is a simple CRUD API application made with Express and documented with Swagger',
        },
        servers: [
            {
                url: 'http://localhost:3000',
                description: 'Development server'
            }
        ],
    },
    apis: ['src/index.js'] // Make sure this path correctly points to your file with Swagger annotations
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));


/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Registers a new user
 *     description: Adds a new user to the database with full name, email, address, and password.
 *     tags:
 *       - Users
 *     operationId: registerUser
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: body
 *         name: body
 *         description: The user's full name, email, address, and password.
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             fullName:
 *               type: string
 *               example: "Valters Jargans"
 *             email:
 *               type: string
 *               example: "valters.walle@gmail.com"
 *             address:
 *               type: string
 *               example: "Zvejnieku iela 13"
 *             password:
 *               type: string
 *               example: "@Jaunaparole111"
 *     responses:
 *       201:
 *         description: User registered successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "User registered successfully"
 *                 id:
 *                   type: string
 *                   example: "507f191e810c19729de860ea"
 *       409:
 *         description: Email already exists.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Email already exists"
 *       422:
 *         description: Missing one or more of the required fields.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "All fields are required (fullName, email, address, password)"
 *       500:
 *         description: Internal server error, such as a database failure.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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
 * @swagger
 * /api/login:
 *   post:
 *     summary: Logs in a user
 *     description: Authenticates a user by their email and password, and returns user details along with access and refresh tokens if successful.
 *     tags:
 *       - Authentication
 *     operationId: loginUser
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: body
 *         name: body
 *         description: User's email and password.
 *         required: true
 *         schema:
 *           type: object
 *           required:
 *             - email
 *             - password
 *           properties:
 *             email:
 *               type: string
 *               example: "valters@gmail.com"
 *             password:
 *               type: string
 *               example: "@Jaunaparole007"
 *     responses:
 *       200:
 *         description: Login successful, returns user details and tokens.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                   example: "507f191e810c19729de860ea"
 *                 fullName:
 *                   type: string
 *                   example: "Valters Jargans"
 *                 email:
 *                   type: string
 *                   example: "valters@gmail.com"
 *                 address:
 *                   type: string
 *                   example: "Zvejnieku iela 13"
 *                 accessToken:
 *                   type: string
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                 refreshToken:
 *                   type: string
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       401:
 *         description: Incorrect password or user does not exist.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Incorrect password or user not found"
 *       422:
 *         description: Missing email or password in the request.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "All fields are required (email, password)"
 *       500:
 *         description: Internal server error, such as a failure in backend operations.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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
 * @swagger
 * /api/refresh-token:
 *   post:
 *     summary: Refreshes an access token
 *     description: Provides a new access token using a refresh token when the current access token is about to expire or has expired.
 *     tags:
 *       - Authentication
 *     operationId: refreshAccessToken
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: body
 *         name: body
 *         description: Refresh token required to obtain a new access token.
 *         required: true
 *         schema:
 *           type: object
 *           required:
 *             - refreshToken
 *           properties:
 *             refreshToken:
 *               type: string
 *               description: Valid refresh token provided during the login or previous token refresh operation.
 *               example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI4bkE2c1d0VDczTXRTdmZKIiwiaWF0IjoxNzQxMDE2OTE4LCJleHAiOjE3NDE2MjE3MTgsInN1YiI6IlJlZnJlc2gifQ.oLmar1R20bInRpydl_7P1jp83u40rYdhQUyrtciFwA"
 *     responses:
 *       200:
 *         description: Access token refreshed successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                   description: New JWT access token for authorization.
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                 refreshToken:
 *                   type: string
 *                   description: Optionally, a new refresh token could also be issued.
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       400:
 *         description: Refresh token is invalid or missing.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid or missing refresh token."
 *       401:
 *         description: Refresh token is expired.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Refresh token expired."
 *       500:
 *         description: Internal server error, such as a failure in backend operations or token generation issues.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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
 * @swagger
 * /api/logout:
 *   post:
 *     summary: Logs out a user
 *     description: Invalidates the user's refresh token and logs out the user by removing their session tokens from the database. Requires a valid access token for authorization.
 *     tags:
 *       - Authentication
 *     operationId: logoutUser
 *     security:
 *       - bearerAuth: []
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         type: string
 *         description: Access token.
 *       - in: body
 *         name: body
 *         required: false
 *         description: Contains the refresh token that needs to be invalidated.
 *         schema:
 *           type: object
 *           properties:
 *             null
 *     responses:
 *       204:
 *         description: Successfully logged out, no content to return.
 *       400:
 *         description: Bad request, typically due to missing or improperly formatted refresh token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Refresh token is required."
 *       401:
 *         description: Unauthorized, typically due to an invalid or expired access token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid or expired access token."
 *       500:
 *         description: Internal server error, indicating failures within backend processes such as database errors.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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
 * @swagger
 * /api/password/reset:
 *   post:
 *     summary: Resets a user's password
 *     description: Allows authenticated users to change their current password to a new one, ensuring they provide the current password for verification.
 *     tags:
 *       - Authentication
 *     operationId: resetUserPassword
 *     security:
 *       - Authorization: []
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         type: string
 *         description: Access token to authenticate the request.
 *       - in: body
 *         name: body
 *         required: true
 *         description: JSON object containing the current and new passwords.
 *         schema:
 *           type: object
 *           required:
 *             - currentPassword
 *             - newPassword
 *           properties:
 *             currentPassword:
 *               type: string
 *               description: The user's current password.
 *               example: "@Jaunaparole111"
 *             newPassword:
 *               type: string
 *               description: The new password that the user wants to set.
 *               example: "@Jaunaparole007"
 *     responses:
 *       200:
 *         description: Password reset successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password reset successfully"
 *       401:
 *         description: Incorrect current password or unauthorized request.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Incorrect password"
 *       422:
 *         description: Validation error for missing or invalid fields.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "All fields are required (currentPassword, newPassword)"
 *       500:
 *         description: Internal server error due to processing issues.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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
 * @swagger
 * /api/user:
 *   get:
 *     summary: Get authenticated user details
 *     description: Retrieves the profile details of the authenticated user. Requires a valid access token for verification and access.
 *     tags:
 *       - User Profile
 *     operationId: getUserDetails
 *     security:
 *       - Authorization: []
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         type: string
 *         description: Access token to authenticate the request.
 *     responses:
 *       200:
 *         description: Successfully retrieved user details.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                   example: "507f1f77bcf86cd799439011"
 *                 fullName:
 *                   type: string
 *                   example: "John Doe"
 *                 email:
 *                   type: string
 *                   example: "john.doe@example.com"
 *                 address:
 *                   type: string
 *                   example: "1234 North Street, New City, EC3A"
 *       401:
 *         description: Unauthorized access, typically due to an invalid or expired access token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid or expired access token."
 *       500:
 *         description: Internal server error, such as a failure in backend processes.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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
 * @swagger
 * /api/user:
 *   put:
 *     summary: Update user profile
 *     description: Allows an authenticated user to update their profile details. Requires a valid access token and all fields (fullName, email, address) must be provided.
 *     tags:
 *       - User Profile
 *     operationId: updateUserProfile
 *     security:
 *       - bearerAuth: []
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         type: string
 *         description: Bearer token to authenticate the request.
 *       - in: body
 *         name: body
 *         required: true
 *         description: New full name, email, and address to update the user profile.
 *         schema:
 *           type: object
 *           properties:
 *             fullName:
 *               type: string
 *               example: "Jane Doe"
 *             email:
 *               type: string
 *               example: "jane.doe@example.com"
 *             address:
 *               type: string
 *               example: "4321 South Street, New City, EC3A"
 *     responses:
 *       200:
 *         description: User profile updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "User profile updated successfully"
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     fullName:
 *                       type: string
 *                       example: "Jane Doe"
 *                     email:
 *                       type: string
 *                       example: "jane.doe@example.com"
 *                     address:
 *                       type: string
 *                       example: "4321 South Street, New City, EC3A"
 *       422:
 *         description: Validation error due to missing required fields.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "All fields are required (fullName, email, address)"
 *       500:
 *         description: Internal server error, such as a failure in backend processes.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unexpected error occurred"
 */
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

