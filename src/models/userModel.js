const Datastore = require('nedb-promises');

const users = Datastore.create({ filename: 'Users.db', autoload: true });

module.exports = { users };