require('dotenv').config();

module.exports = {
    port: process.env.PORT || 3000,
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
    accessTokenExpiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '30m', // Default value
    refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d', // Default value
    mongodbURI: process.env.MONGODB_URI || '',
};
