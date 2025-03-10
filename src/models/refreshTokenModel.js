const mongoose = require('mongoose');

//const userRefreshTokens = Datastore.create({ filename: 'UserRefreshTokens.db', autoload: true });

const Schema = mongoose.Schema;

const userRefreshTokenSchema = new Schema({
    token: String, //"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJsVlBEbG9mRXJXU1FwcE5KIiwiaWF0IjoxNzQxNjE1MDkxLCJleHAiOjE3NDIyMTk4OTEsInN1YiI6IlJlZnJlc2gifQ.KKRP-b1eTu7BxNrEoQ27FfLvKJpTnITKxKVnCTBayU8"
    userId: String, //"lVPDlofErWSQppNJ"
});

const userRefreshTokens = mongoose.model("userRefreshTokens", userRefreshTokenSchema);

module.exports = { userRefreshTokens };
