const express = require("express");
const router = express.Router();
const {BusinessUser, BusinessUserAudit,
  validateBussinessUserPost, validateBusinessUserPut,
  validateRefreshToken, validateEmail, validateBusinessUserLogin,
  validateChangePassword, validateResetPassword} = require("../models/businessUser");
const _ = require("lodash");
const mongoose = require ('mongoose');
const util = require("util");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const config = require("config");
const { Token } = require("../models/emailVerificationtoken");
const { BUSINESSUSER_CONSTANT, AUTH_CONSTANTS } = require("../config/constant.js");
const response = require("../service/response");
mongoose.set("debug", true);

router.get("/", async (req, res)  => {
  const id = req.params.id;
  const businesUser = BusinessUser.findById(id, function(err, data) {
    if (err){
      console.log(err);
      res.status(400).send({
        statusCode: 400,
        message:  "Failure",
        data: BUSINESSUSER_CONSTANT.INVALID_BUSINESSUSER
  })
}
  else{
    const response = _.pick(businesUser, ["Name", "_id"]);
  res.send({ statusCode: 200, message: 'successful', response });

  };
  });


});


// Create a new User
router.post("/", async (req, res) => {
    const { error } = validateBussinessUserPost(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    let businessUser = await BusinessUser.findOne({
      $or: [{ email: req.body.email.toLowerCase() }, { phone: req.body.phone }],
    });
    if (businessUser) {
        if (req.body.email === businessUser.email)
          return response.error(res, BUSINESSUSER_CONSTANT.EMAIL_ALREADY_EXISTS, 400);
          if (req.body.cacCode === businessUser.cacCode)
          return response.error(res, BUSINESSUSER_CONSTANT.INVALID_CACCERTIFICATE, 400);
         if (req.body.phone === businessUser.phone)
          return response.error(res, BUSINESSUSER_CONSTANT.PHONE_ALREADY_EXISTS, 400);  
      }
      const email = req.body.email.toLowerCase();
  const { Name, phone, password, cacCertificate, cacCode } = req.body;

  console.log({ Name, cacCertificate, cacCode, phone, password, email });

  try {
    //instantiate BusinessUser model
    businessUser = new BusinessUser({
      Name,
      email,
      phone,
      cacCode,
      password,
      cacCertificate,
      status: "active"
    })


  //create salt for businessuser password hash
    const salt = await bcrypt.genSalt(10);

    //hash password and replace businessuser password with the hashed password
    businessUser.password = await bcrypt.hash(password, salt);

    // save businessuser to db
    await businessUser.save();

    // Create a verification token for this user
    var token = new Token({
      _businessUserId: BusinessUser._id,
      token: crypto.randomBytes(16).toString("hex"),
    });

    // Save the verification token
    token.save(function (err) {
      if (err) return response.error(res, err.message, 500);
    });

      return response.success(res, BUSINESSUSER_CONSTANT.VERIFICATION_EMAIL_SENT);
  } catch (err) {
    console.error(err.message);
    return response.error(res, err.message, 500);
  }
    

  });

  // verify email
router.get("/verify/:token", async (req, res) => {
  const { token } = req.params;
  if (!token)
    return response.redirect(res, BUSINESSUSER_CONSTANT.VERIFICATION_FAILURE);
  // if(!token) return response.error(res, BUSINESSUSER_CONSTANT.VERIFICATION_FAILURE);
  console.log("token isssss:::::" + token);

  // Find a matching token
  Token.findOne({ token }, function (err, token) {
    if (!token)
      return response.redirect(res, BUSINESSUSER_CONSTANT.VERIFICATION_FAILURE);
    // if (!token) return response.error(res, BUSINESSUSER_CONSTANT.VERIFICATION_FAILURE);

    // If we found a token, find a matching businessUser
    BusinessUser.findOne({ _id: token._businessUserId }, function (err, businessUser) {
      if (!businessUser) return response.redirect(res, BUSINESSUSER_CONSTANT.INVALID_USER);
      // if (!user) return response.error(res, BUSINESSUSER_CONSTANT.INVALID_USER);
      if (businessUser.isVerified)
        return response.redirect(res, BUSINESSUSER_CONSTANT.USER_ALREADY_VERIFIED);
      // if (user.isVerified) return response.error(res, BUSINESSUSER_CONSTANT.USER_ALREADY_VERIFIED);

      // Verify and save the businessUser
      businessUser.isVerified = true;
      businessUser.status = "active";
      businessUser.save(function (err) {
        if (err) return response.error(res, err.message);
        return response.redirect(res);
      });
    });
  });
});


  router.post("/resend", async (req, res) => {
    // Check for validation errors
    const { error } = validateEmail(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    const { email } = req.body;
    console.log("email isssss:::::" + email);
  
    const businessUser = await BusinessUser.findOne({ email });
    if (!businessUser) return response.error(res, BUSINESSUSER_CONSTANT.INVALID_BUSINESSUSER);
    if (businessUser.isVerified)
      return response.error(res, BUSINESSUSER_CONSTANT.USER_ALREADY_VERIFIED);
  
    // Create a verification token for this user
    var token = new Token({
      _businessUserId: businessUser._id,
      token: crypto.randomBytes(16).toString("hex"),
    });
  
    // Save the verification token
    token.save(function (err) {
      if (err) return response.error(res, err.message, 500);
    });
  
    return response.success(res, BUSINESSUSER_CONSTANT.VERIFICATION_EMAIL_SENT);
  }); 

  router.post("/login", async (req, res) => {
    const { error } = validateBusinessUserLogin(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    let criteria = {};
    if (req.body.email && req.body.email != "")
      criteria.email = req.body.email.toLowerCase();
  
    let businessUser = await BusinessUser.findOne(criteria);
  
    if (!businessUser) return response.error(res, AUTH_CONSTANTS.INVALID_CREDENTIALS);
  
    if (!businessUser.isVerified)
      return response.error(res, BUSINESSUSER_CONSTANT.NOT_YET_VERIFIED);
  
    if (businessUser.status != "active")
      return response.error(res, AUTH_CONSTANTS.INACTIVE_ACCOUNT);
  
    const validPassword = await bcrypt.compare(req.body.password, businessUser.password);
    if (!validPassword)
      return response.error(res, AUTH_CONSTANTS.INVALID_CREDENTIALS);
  
    // create access token
    const payload = { businessUserId: businessUser._id, email: businessUser.email };
    const secret = config.get("jwtPrivateKey");
    const options = {
      expiresIn: "1d",
      issuer: "earntogive.com",
      audience: businessUser._id.toString(),
    };
  
    const token = await jwt.sign(payload, secret, options);
  
    // create refresh token
    const refreshTokenPayload = {
      businessUserId: businessUser._id,
      email: businessUser.email,
    };
    const refreshTokenSecret = config.get("jwtRefreshTokenPrivateKey");
    const refreshTokenOptions = {
      expiresIn: "1y",
      issuer: "earntogive.com",
      audience: businessUser._id.toString(),
    };
  
    const refreshToken = await jwt.sign(
      refreshTokenPayload,
      refreshTokenSecret,
      refreshTokenOptions,
    );
  
    businessUser.accessToken = token;
    businessUser.refreshToken = refreshToken;
    businessUser.lastLogin = new Date();
    await businessUser.save();
    businessUser.businessUserId = businessUser._id;
  
    let details = _.pick(businessUser, [
      "businessUserId",
      "Name",
      "cacCode",
      "cacCertificate",
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
  
    let businessUser = await BusinessUser.findById(req.jwtData.businessUserId);
    if (!businessUser) return response.error(res, AUTH_CONSTANTS.INVALID_USER);
  
    const { oldPassword, newPassword } = req.body;
  
    const validPassword = await bcrypt.compare(oldPassword, businessUser.password);
    if (!validPassword)
      return response.error(res, AUTH_CONSTANTS.INVALID_PASSWORD);
  
    //create salt for user password hash
    const salt = await bcrypt.genSalt(10);
  
    //hash password and replace user password with the hashed password
    let encryptPassword = await bcrypt.hash(newPassword, salt);
  
    businessUser.password = encryptPassword;
    await businessUser.save();
    return response.success(res, AUTH_CONSTANTS.PASSWORD_CHANGE_SUCCESS);
  });
  
  router.post("/password/forgot", async (req, res) => {
    // Check for validation errors
    const { error } = validateEmail(req.body);
    if (error) return response.validationErrors(res, error.details[0].message);
  
    const { email } = req.body;
    console.log("email isssss:::::" + email);
  
    const businessUser = await BusinessUser.findOne({ email });
    if (!businessUser) return response.error(res, BUSINESSUSER_CONSTANT.INVALID_USER);
  
    const resetToken = crypto.randomBytes(20).toString("hex");
    businessUser.resetPasswordToken = resetToken;
    businessUser.resetPasswordExpires = Date.now() + 3600000; //expires in an hour
    businessUser.save(function (err) {
      if (err) return response.error(res, err.message, 500);
    });
  
    return response.success(res, BUSINESSUSER_CONSTANT.RESET_PASSWORD_EMAIL_SENT);
  });
  
  router.get("/password/forgot/:token", async (req, res) => {
    const { token } = req.params;
  
    // Find a matching token
    businessUser = await BusinessUser.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!businessUser) return response.error(res, BUSINESSUSER_CONSTANT.INVALID_USER);
  
    // res.redirect('http://frontend_form_url');
    return response.success(
      res,
      "Waiting for frontend to provide a password form url to redirect to",
    );
  });
  
  router.post("/password/reset/:token", async (req, res) => {
    const { error } = validateResetPassword(req.body);
    if (error) return response.error(res, error.details[0].message);
  
    const { newPassword, confirmNewPassword } = req.body;
  
    if (newPassword !== confirmNewPassword)
      return response.error(res, BUSINESSUSER_CONSTANT.PASSWORD_MISMATCH);
  
    try {
      businessUser = await BusinessUser.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() },
      });
      if (!businessUser) return response.success(res, BUSINESSUSER_CONSTANT.INVALID_USER);
  
      //create salt for user password hash
      const salt = await bcrypt.genSalt(10);
  
      //hash password and replace user password with the hashed password
      businessUser.password = await bcrypt.hash(newPassword, salt);
      businessUser.resetPasswordToken = undefined;
      businessUser.resetPasswordExpires = undefined;
  
      // save user to db
      await businessUser.save();
  
      return response.success(res, BUSINESSUSER_CONSTANT.PASSWORD_CHANGE_SUCCESS);
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
        businessUser: decoded.businessUserId,
        email: decoded.email,
      };
      const secret = config.get("jwtPrivateKey");
      const options = {
        expiresIn: "1d",
        issuer: "earntogive.com",
        audience: decoded.businessUserId,
      };
  
      const token = await jwt.sign(payload, secret, options);
  
      // create new refresh token
      const newRefreshTokenPayload = {
        businessUserId: decoded.businessUserId,
        email: decoded.email,
      };
      const newRefreshTokenSecret = config.get("jwtRefreshTokenPrivateKey");
      const newRefreshTokenOptions = {
        expiresIn: "1y",
        issuer: "earntogive.com",
        audience: decoded.businessUserId,
      };
  
      const newRefreshToken = await jwt.sign(
        newRefreshTokenPayload,
        newRefreshTokenSecret,
        newRefreshTokenOptions,
      );
  
      // get user and replace access token
      businessUser = await BusinessUser.findById(decoded.businessUserId);
      businessUser.accessToken = token;
      businessUser.refreshToken = newRefreshToken;
  
      await businessUser.save();
      return response.withData(res, { token: token, refreshToken: refreshToken });
    } catch (error) {
      return response.error(res, error.message);
    }
  });
  
  async function logCurrentBusinessUserState(businessUser) {
    let auditbusinessUser = new BusinessUserAudit({
      businessUserId: businessUser._id,
      fullName: businessUser.fullName,
      phone: businessUser.phone,
      email: businessUser.email,
      stateId: businessUser.stateId,
      address: businessUser.address,
      status: businessUser.status,
      profilePic: businessUser.profilePic,
      createdBy: businessUser.createdBy,
      modifiedBy: businessUser.modifiedBy,
      modifiedDate: businessUser.modifiedDate,
    });
    await auditbusinessUser.save();
  }

 
 
 
 

router.put("/", async (req, res) => {
  const { error } = validateBusinessUserPut(req.body);
  if (error)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: error.details[0].message,
    });
    
  var businessUser = BusinessUser.findOne(req.body);
  if (!businessUser)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: BUSINESSUSER_CONSTANT.INVALID_USER,
      
    });
  await logCurrentBusinessUserState(businessUser);

  const { Name, phone , email } = req.body;
  try {
    businessUser = new BusinessUser({
      Name,
      phone,
      email
    });

    // save category to db
    await businessUser.save();
  } catch (err) {
    console.error(err.message);
    return response.error(res, err.message, 500);   
  }

  let resp = _.pick(businessUser, ["Name", "phone", "email"]);

  res.send({statusCode: 200, message: "Success", data: resp });
});
 
 
 
 


module.exports = router;