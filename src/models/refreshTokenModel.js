const Datastore = require('nedb-promises');

const userRefreshTokens = Datastore.create({ filename: 'UserRefreshTokens.db', autoload: true });

module.exports = { userRefreshTokens };