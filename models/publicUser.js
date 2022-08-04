const mongoose = require("mongoose");
const Joi = require("joi");

const PublicUserSchema = new mongoose.Schema({
    publicUserId: String,
    firstName: { type: String, default: "" },
    lastName: { type: String, default: "" },
    phone: { type: String, default: "" },
    email: { type: String, default: "", required: true, unique: true },
    password: { type: String, default: "" },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    isVerified: { type: Boolean, default: true },
    accessToken: { type: String, default: "" },
    refreshToken: { type: String, default: "" },
    status: { type: String, enum: ["active", "inactive", "blocked"], default: "inactive" },
    profilePic: { type: String, default: "" },
    createdBy: String,
    modifiedDate: Number,
    lastLogin: { type: Date }
}, { timestamps: true });
const PublicUser = mongoose.model("PublicUser", PublicUserSchema);

const publicUserAuditSchema = new mongoose.Schema({
    PublicUserId: String,
    firstName: String,
    lastName: String,
    phone: String,
    email: String,
    status: String,
    profilePic: String,
    createdBy: String,
    modifiedBy: String,
    modifiedDate: Number,
    lastLogin: Date
});

const PublicUserAudit = mongoose.model("publicUseraudit", publicUserAuditSchema);

function validatePublicUserPost(publicUser) {
    const schema = {
        firstName: Joi.string().min(2).max(200).required(),
        lastName: Joi.string().min(2).max(200).required(),
        password: Joi.string().min(6).max(20).required(),
        email: Joi.string().email().required(),
        phone: Joi.string(),
    };
    return Joi.validate(publicUser, schema);
}
function validatePublicUserLogin(publicUser) {
    const schema = {
        email: Joi.string().min(6).max(200).required(),
        password: Joi.string().min(6).max(200).required(),
    };
    return Joi.validate(publicUser, schema);
}
function validatePublicUserPut(publicUser) {
    const schema = {
        businessUserId: Joi.string().min(1).max(200),
        firstName: Joi.string().min(2).max(200),
        email: Joi.string().email(),
        phone: Joi.string(),
        profilePic: Joi.string().min(1).max(200).allow(""),
        status: Joi.string().valid(["active", "inactive", "blocked"])
    };
    return Joi.validate(publicUser, schema);
}
function validateChangePassword(publicUser) {
    const schema = {
        oldPassword: Joi.string().min(1).max(200).required(),
        newPassword: Joi.string().min(1).max(200).required(),
        confirmNewPassword: Joi.any().valid(Joi.ref('newPassword')).required().options({ language: { any: { allowOnly: 'must match newPassword' } } })
    };
    return Joi.validate(publicUser, schema);
}

function validateResetPassword(publicUser) {
    const schema = {
        newPassword: Joi.string().min(6).max(200).required(),
        confirmNewPassword: Joi.string().min(6).max(200).required()
    };
    return Joi.validate(publicUser, schema);
}
function validateEmail(publicUser) {
    const schema = {
        email: Joi.string().email().required()
    };
    return Joi.validate(publicUser, schema);
}



module.exports.PublicUser = PublicUser;
module.exports.PublicUserAudit = PublicUserAudit;
module.exports.validatePublicUserPost = validatePublicUserPost;
module.exports.validatePublicUserPut = validatePublicUserPut;
module.exports.validatePublicUserLogin = validatePublicUserLogin;
module.exports.validateChangePassword = validateChangePassword;
module.exports.validateResetPassword = validateResetPassword;
module.exports.validateEmail = validateEmail;