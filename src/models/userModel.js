const mongoose = require('mongoose');

//const users = Datastore.create({ filename: 'Users.db', autoload: true });

const Schema = mongoose.Schema;

const userSchema = new Schema({
    fullName: String,       //"Valters Jargans"
    email: String,          //"valters.walle@gmail.com"
    address: String,        //"Zvejnieku iela 13"
    password: String,       //"$2b$12$1CoqZ75FaqryXODle4dYbet3QbKBobyB3QFtawtA0ED1uYIcSa6ua"
});

const users = mongoose.model("users", userSchema);

module.exports = { users };
