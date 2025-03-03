require('dotenv').config();

module.exports = {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
    accessTokenExpiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '15m', // Default value
    refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d', // Default value
};
