const Datastore = require('nedb-promises');

const users = Datastore.create({ filename: 'Users.db', autoload: true });
const userRefreshTokens = Datastore.create({ filename: 'UserRefreshTokens.db', autoload: true });

module.exports = { users, userRefreshTokens };