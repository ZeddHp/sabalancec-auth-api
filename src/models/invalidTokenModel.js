const Datastore = require('nedb-promises');

const userInvalidTokens = Datastore.create({ filename: 'UserInvalidTokens.db', autoload: true });

module.exports = { userInvalidTokens };