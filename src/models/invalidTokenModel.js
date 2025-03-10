const mongoose = require('mongoose');

//const userInvalidTokens = Datastore.create({ filename: 'UserInvalidTokens.db', autoload: true });

const Schema = mongoose.Schema;

const userInvalidTokenSchema = new Schema({
    userId: String,                     //"lVPDlofErWSQppNJ"
    expirationTime: Date,               //1741613834
    accessToken: String,                //"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJsVlBEbG9mRXJXU1FwcE5KIiwiaWF0IjoxNzQxNjEyMDM0LCJleHAiOjE3NDE2MTM4MzQsInN1YiI6IkF1dGhvcml6YXRpb24ifQ.psgCZ9c2iUb_CsTTC3oNjTV2VDrRkDGzc9m27vRK7hc"
});

const userInvalidTokens = mongoose.model("userInvalidTokens", userInvalidTokenSchema);

module.exports = { userInvalidTokens };
