const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");

const DonateSchema = new mongoose.Schema({
    full_name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,  
    },
    amount: {
        type: Number,
        required: true,
    },
    reference: {
        type: String,
        required: true
    }
});
const Donate = mongoose.model("Donate", DonateSchema);


module.exports.Donate = Donate;