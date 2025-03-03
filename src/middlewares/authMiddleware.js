const jwt = require('jsonwebtoken'); // JWT MODULE
const { users } = require('../models/userModel'); // USER MODEL
const { userInvalidTokens } = require('../models/invalidTokenModel'); // INVALID TOKEN MODEL
const config = require('../config/config'); // CONFIGURATION FILE

/**
 * Middleware to verify the access token
 * @param {Object} req.headers.authorization - Access Token
 * @returns {Object} { accessToken, user }
*/
async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization;

    if (!accessToken) {
        return res.status(401).json({ error: 'Access token is required' });
    }

    // Check if the access token is in the invalid tokens list
    if (await userInvalidTokens.findOne({ accessToken })) {
        return res.status(401).json({ error: 'Access token invalid' });
    }

    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);

        req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
        req.user = await users.findOne({ _id: decodedAccessToken.userId });

        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: 'Access token expired', code: 'AccessTokenExpired' });
        } else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: 'Access token invalid', code: 'AccessTokenInvalid' })
        } else {
            return res.status(500).json({ error: error.message });
        }
    }
}

module.exports = { ensureAuthenticated };
