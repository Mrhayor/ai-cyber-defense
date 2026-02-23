const mongoose = require("mongoose");

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log("Connected to MongoDB Atlas");
})
.catch((err) => {
    console.log("Failed to connect to MongoDB", err);
});

const UserSchema = new mongoose.Schema({
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});

const collection = new mongoose.model("Collection1", UserSchema);

module.exports = collection;


//password
//1fokYEMUuPCRwyKF