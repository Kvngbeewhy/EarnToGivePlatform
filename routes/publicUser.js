const express = require("express");
const router = express.Router();
const config = require ("config");
const { PublicUser, validateResetPassword,
   validateChangePassword, PublicUserAudit, 
   validateEmail,validatePublicUserPut,
    validatePublicUserPost, validatePublicUserLogin} =  require("../models/publicUser");
const { PUBLICUSER_CONSTANT, AUTH_CONSTANTS } = require("../config/constant.js");
const response = require("../service/response");
const _ = require("lodash");
const mongoose = require ('mongoose');
const util = require("util");
const { Token } = require("../models/emailVerificationtoken");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
mongoose.set("debug", true);


router.post("/", async (req,res) => {
    const { error } = validatePublicUserPost(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
    
    let publicUser = PublicUser.findOne({
        $or:[{ email: req.body.email.toLowerCase() }, {}]
    });
    if (publicUser) {
        if (req.body.email === publicUser.email)
          return response.error(res, PUBLICUSER_CONSTANT.EMAIL_ALREADY_EXISTS, 400);
         if (req.body.phone === publicUser.phone)
          return response.error(res, PUBLICUSER_CONSTANT.PHONE_ALREADY_EXISTS, 400);  
      }
      const email = req.body.email.toLowerCase();
  const { firstName, lastName, phone, password } = req.body;

  console.log({ firstName, lastName, phone, password, email });

  try {
    //instantiate PublicUser model
    publicUser = new PublicUser({
      firstName,
      lastName,
      email,
      phone,
      password,
      status: "active"
    })


  //create salt for publicUser password hash
    const salt = await bcrypt.genSalt(10);

    //hash password and replace publicUser password with the hashed password
    publicUser.password = await bcrypt.hash(password, salt);

    // save businessuser to db
    await publicUser.save();

    // Create a verification token for this user
    var token = new Token({
      _publicUserId: PublicUser._id,
      token: crypto.randomBytes(16).toString("hex"), 
    });

    // Save the verification token
    token.save(function (err) {
      if (err) return response.error(res, err.message, 500);
    });

      return response.success(res, PUBLICUSER_CONSTANT.VERIFICATION_EMAIL_SENT);
  } catch (err) {
    console.error(err.message);
    return response.error(res, err.message, 500);
  }
    

  });

  router.post("/resend", async (req, res) => {
    // Check for validation errors
    const { error } = validateEmail(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    const { email } = req.body;
    console.log("email isssss:::::" + email);
  
    const publicUser = await PublicUser.findOne({ email });
    if (!publicUser) return response.error(res, PUBLICUSER_CONSTANT.INVALID_USER);
    if (publicUser.isVerified)
      return response.error(res, PUBLICUSER_CONSTANT.USER_ALREADY_VERIFIED);
  
    // Create a verification token for this user
    var token = new Token({
      publicUserId: publicUser._id,
      token: crypto.randomBytes(16).toString("hex"),
    });
  
    // Save the verification token
    token.save(function (err) {
      if (err) return response.error(res, err.message, 500);
    });
  
    return response.success(res, PUBLICUSER_CONSTANT.VERIFICATION_EMAIL_SENT);
  }); 

  router.post("/login", async (req, res) => {
    const { error } = validatePublicUserLogin(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    let criteria = {};
    if (req.body.email && req.body.email != "")
      criteria.email = req.body.email.toLowerCase();
  
    let publicUser = await PublicUser.findOne(criteria);
  
    if (!publicUser) return response.error(res, AUTH_CONSTANTS.INVALID_CREDENTIALS);
  
    if (!publicUser.isVerified)
      return response.error(res, PUBLICUSER_CONSTANT.NOT_YET_VERIFIED);
  
    if (publicUser.status != "active")
      return response.error(res, AUTH_CONSTANTS.INACTIVE_ACCOUNT);
  
    const validPassword = await bcrypt.compare(req.body.password, publicUser.password);
    if (!validPassword)
      return response.error(res, AUTH_CONSTANTS.INVALID_CREDENTIALS);
  
    // create access token
    const payload = { publicUserId: publicUser._id, email: publicUser.email };
    const secret = config.get("jwtPrivateKey");
    const options = {
      expiresIn: "1d",
      issuer: "earntogive.com",
      audience: publicUser._id.toString(),
    };
  
    const token = await jwt.sign(payload, secret, options);
  
    // create refresh token
    const refreshTokenPayload = {
      publicUserId: publicUser._id,
      email: publicUser.email,
    };
    const refreshTokenSecret = config.get("jwtRefreshTokenPrivateKey");
    const refreshTokenOptions = {
      expiresIn: "1y",
      issuer: "earntogive.com",
      audience: publicUser._id.toString(),
    };
  
    const refreshToken = await jwt.sign(
      refreshTokenPayload,
      refreshTokenSecret,
      refreshTokenOptions,
    );
  
    publicUser.accessToken = token;
    publicUser.refreshToken = refreshToken;
    publicUser.lastLogin = new Date();
    await publicUser.save();
    publicUser.publicUserId = publicUser._id;
  
    let details = _.pick(publicUser, [
      "publicUserId",
      "firstName",
      "phone",
      "email",
      "status",
      "profilePic",
      "lastLogin",
    ]);
    return response.withData(res, {
      token: token,
      refreshToken: refreshToken,
      details: details,
    });
  });

  router.post("/password/change", async (req, res) => {
    const { error } = validateChangePassword(req.body);
    if (error) return response.error(res, error.details[0].message);
  
    let publicUser = await PublicUser.findById(req.jwtData.publicUserId);
    if (!publicUser) return response.error(res, AUTH_CONSTANTS.INVALID_USER);
  
    const { oldPassword, newPassword } = req.body;
  
    const validPassword = await bcrypt.compare(oldPassword, publicUser.password);
    if (!validPassword)
      return response.error(res, AUTH_CONSTANTS.INVALID_PASSWORD);
  
    //create salt for user password hash
    const salt = await bcrypt.genSalt(10);
  
    //hash password and replace user password with the hashed password
    let encryptPassword = await bcrypt.hash(newPassword, salt);
  
    publicUser.password = encryptPassword;
    await publicUser.save();
    return response.success(res, AUTH_CONSTANTS.PASSWORD_CHANGE_SUCCESS);
  });
  
  router.post("/password/forgot", async (req, res) => {
    // Check for validation errors
    const { error } = validateEmail(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    const { email } = req.body;
    console.log("email isssss:::::" + email);
  
    const publicUser = await PublicUser.findOne({ email });
    if (!publicUser) return response.error(res, PUBLICUSER_CONSTANT.INVALID_USER);
  
    const resetToken = crypto.randomBytes(20).toString("hex");
    publicUser.resetPasswordToken = resetToken;
    publicUser.resetPasswordExpires = Date.now() + 3600000; //expires in an hour
    publicUser.save(function (err) {
      if (err) return response.error(res, err.message, 500);
    });
  
    return response.success(res, PUBLICUSER_CONSTANT.RESET_PASSWORD_EMAIL_SENT);
  });

  router.get("/password/forgot/:token", async (req, res) => {
    const { token } = req.params;
  
    // Find a matching token
    publicUser = await PublicUser.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!publicUser) return response.error(res, PUBLICUSER_CONSTANT.INVALID_USER);
  
    // res.redirect('http://frontend_form_url');
    return response.success(
      res,
      "Waiting for frontend to provide a password form url to redirect to",
    );
  });
  
  router.post("/password/reset/token", async (req, res) => {
    const { error } = validateResetPassword(req.body);
    if (error) return response.error(res, error.details[0].message);
  
    const { newPassword, confirmNewPassword } = req.body;
  
    if (newPassword !== confirmNewPassword)
      return response.error(res, PUBLICUSER_CONSTANT.PASSWORD_MISMATCH);
  
    try {
      publicUser = await PublicUser.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() },
      });
      if (!publicUser) return response.success(res, PUBLICUSER_CONSTANT.INVALID_USER);
  
      //create salt for user password hash
      const salt = await bcrypt.genSalt(10);
  
      //hash password and replace user password with the hashed password
      publicUser.password = await bcrypt.hash(newPassword, salt);
      publicUser.resetPasswordToken = undefined;
      publicUser.resetPasswordExpires = undefined;
  
      // save user to db
      await publicUser.save();
  
      return response.success(res, PUBLICUSER_CONSTANT.PASSWORD_CHANGE_SUCCESS);
    } catch (err) {
      console.error(err.message);
      return response.error(res, err.message, 500);
    }
  });

  router.post("/refresh-token", async (req, res) => {
    const { error } =   (req.body);
    if (error) return response.error(res, error.details[0].message);
  
    const { refreshToken } = req.body;
  
    try {
      const decoded = await jwt.verify(
        refreshToken,
        config.get("jwtRefreshTokenPrivateKey"),
      );
      console.log(decoded);
  
      if (!decoded) return response.error(res);
  
      // create new access token
      const payload = {
        publicUser: decoded.publicUserId,
        email: decoded.email,
      };
      const secret = config.get("jwtPrivateKey");
      const options = {
        expiresIn: "1d",
        issuer: "earntogive.com",
        audience: decoded.publicUserId,
      };
  
      const token = await jwt.sign(payload, secret, options);
  
      // create new refresh token
      const newRefreshTokenPayload = {
        publicUserId: decoded.publicUserId,
        email: decoded.email,
      };
      const newRefreshTokenSecret = config.get("jwtRefreshTokenPrivateKey");
      const newRefreshTokenOptions = {
        expiresIn: "1y",
        issuer: "earntogive.com",
        audience: decoded.publicUserId,
      };
  
      const newRefreshToken = await jwt.sign(
        newRefreshTokenPayload,
        newRefreshTokenSecret,
        newRefreshTokenOptions,
      );
  
      // get user and replace access token
      publicUser = await PublicUser.findById(decoded.publicUserId);
      publicUser.accessToken = token;
      publicUser.refreshToken = newRefreshToken;
  
      await publicUser.save();
      return response.withData(res, { token: token, refreshToken: refreshToken });
    } catch (error) {
      return response.error(res, error.message);
    }
  });
  
  async function logCurrentPublicUserState(publicUser) {
    let publicUserAudit = new PublicUserAudit({
      publicUserId: publicUser._id,
      fullName: publicUser.fullName,
      phone: publicUser.phone,
      email: publicUser.email,
      stateId: publicUser.stateId,
      address: publicUser.address,
      status: publicUser.status,
      profilePic: publicUser.profilePic,
      createdBy: publicUser.createdBy,
      modifiedBy: publicUser.modifiedBy,
      modifiedDate: publicUser.modifiedDate,
    });
    await publicUserAudit .save();
  }


  router.put("/", async (req, res) => {
    const { error } = validatePublicUserPut(req.body);
    if (error)
      return res.status(400).send({
        statusCode: 400,
        message: "Failure",
        data: error.details[0].message,
      });
      
    var publicUser = PublicUser.findOne(req.body);
    if (!publicUser)
      return res.status(400).send({
        statusCode: 400,
        message: "Failure",
        data: PUBLICUSER_CONSTANT.INVALID_USER,
        
      });
    await logCurrentPublicUserState(publicUser);
  
    const { phone , email } = req.body;
    try {
      publicUser = new PublicUser({
        phone,
        email
      });
  
      // save category to db
      await publicUser.save();
    } catch (err) {
      console.error(err.message);
      return response.error(res, err.message, 500);   
    }
  
    let resp = _.pick(publicUser, ["Name", "phone", "email"]);
  
    res.send({statusCode: 200, message: "Success", data: resp });
  });
   
   
   
  
module.exports = router