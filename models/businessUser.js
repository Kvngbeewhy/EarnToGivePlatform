const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");

const BusinessUserSchema = new mongoose.Schema({
    businessUserId: String,
    Name: { type: String, default: "" },
    phone: { type: String, default: "" },
    cacCertificate: { type: String, default: ""},
    caCode: { type: String, default: ""},
    Address: { type: String, default: ""},
    email: { type: String, default: "", required: true, unique: true },
    password: { type: String, default: "" },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    isVerified: { type: Boolean, default: true },
    accessToken: { type: String, default: "" },
    refreshToken: { type: String, default: "" },
    status: { type: String, enum: ["active", "inactive", "blocked"], default: "inactive" },
    profilePic: { type: String, default: "" },
    modifiedDate: Number,
    lastLogin: { type: Date }
}, { timestamps: true });
const BusinessUser = mongoose.model("BusinessUser", BusinessUserSchema);

const businessUserAuditSchema = new mongoose.Schema({
    businessUserId: String,
    Name: String,
    cacCode: String,
    cacCertificate: String,
    phone: String,
    email: String,
    status: String,
    profilePic: String,
    createdBy: String,
    modifiedBy: String,
    modifiedDate: Number,
    lastLogin: Date
});

const BusinessUserAudit = mongoose.model("BussinessUseraudit", businessUserAuditSchema);

function validateBussinessUserPost(businessUser) {
    const schema = {
        Name: Joi.string().min(2).max(200).required(),
        password: Joi.string().min(6).max(20).required(),
        email: Joi.string().email().required(),
        cacCode: Joi.string(),
        cacCertificate: Joi.string(),
        phone: Joi.string(),
    };
    return Joi.validate(businessUser, schema);
}
function validateBusinessUserPut(businessUser) {
    const schema = {
        businessUserId: Joi.string().min(1).max(200),
        Name: Joi.string().min(2).max(200),
        email: Joi.string().email(),
        phone: Joi.string(),
        profilePic: Joi.string().min(1).max(200).allow(""),
        status: Joi.string().valid(["active", "inactive", "blocked"])
    };
    return Joi.validate(businessUser, schema);
}
function validateRefreshToken(businessUser) {
    const schema = {
        refreshToken: Joi.string().min(32).max(1000).required()
    };
    return Joi.validate(businessUser, schema);
}
function validateEmail(businessUser) {
    const schema = {
        email: Joi.string().email().required()
    };
    return Joi.validate(businessUser, schema);
}
function validateBusinessUserLogin(businessUser) {
    const schema = {
        email: Joi.string().min(6).max(200).required(),
        password: Joi.string().min(6).max(200).required(),
    };
    return Joi.validate(businessUser, schema);
}

function validateChangePassword(businessUser) {
    const schema = {
        oldPassword: Joi.string().min(1).max(200).required(),
        newPassword: Joi.string().min(1).max(200).required(),
        confirmNewPassword: Joi.any().valid(Joi.ref('newPassword')).required().options({ language: { any: { allowOnly: 'must match newPassword' } } })
    };
    return Joi.validate(businessUser, schema);
}

function validateResetPassword(businessUser) {
    const schema = {
        newPassword: Joi.string().min(6).max(200).required(),
        confirmNewPassword: Joi.string().min(6).max(200).required()
    };
    return Joi.validate(businessUser, schema);
}



module.exports.BusinessUser = BusinessUser;
module.exports.BusinessUserAudit = BusinessUserAudit;
module.exports.validateBussinessUserPost = validateBussinessUserPost;
module.exports.validateRefreshToken = validateRefreshToken;
module.exports.validateEmail = validateEmail;
module.exports.validateBusinessUserLogin = validateBusinessUserLogin;
module.exports.validateChangePassword = validateChangePassword;
module.exports.validateResetPassword = validateResetPassword;
module.exports.validateBusinessUserPut = validateBusinessUserPut;