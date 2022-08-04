const express = require('express');
const _ = require("lodash");
const router = express.Router();
const { AdminLog, 
      validateAdminLogPut, AdminLogAudit} = require("../models/adminlog");
const mongoose = require ('mongoose');
const config = require("config");
const { ADMINLOG_CONSTANT, AUTH_CONSTANTS } = require("../config/constant.js");
const response = require("../service/response");
mongoose.set("debug", true);

router.post('/', async(req,res) => {
  let { email, password, createdby } = req.body;

  try{
    adminLog = new AdminLog({
      email,
      password,
      createdby
    });

    await adminLog.save();
      return response.success(res, ADMINLOG_CONSTANT.LOG_CREATED);
    } catch (err) {
      console.error(err.message);
      return response.error(res, err.message, 500);
  }
  
});

router.put('/update', async(req,res) => {
  const { error } = validateAdminLogPut(req.body);
  if (error)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: error.details[0].message,
    });

    var adminLog = await AdminLog.findOne(req.params.id);
    if (!adminLog)
      return res.status(400).send({
        statusCode: 400,
        message: "Failure",
        data: ADMINLOG_CONSTANT.INVALID_ADMINLOG,
      });
    await logCurrentAdminLogState(adminLog);
  
    const {email,password,
       lastmodifiedBy} = req.body;
    try {
      adminLog = new AdminLog({
        password, email, 
        lastmodifiedBy
      });
  
      // save adminLog to db
      await adminLog.update();
    } catch (err) {
      console.error(err.message);
      return response.error(res, err.message, 500);
    }
  
    let resp = _.pick(adminLog, ["password", "email", "lastmodifiedby"]);
  
    res.send({ statusCode: 200, message: "Success", data: resp });
  
});


router.delete("/", async (req, res) => {
  console.log(req.body);
  var adminLog = AdminLog.findByIdAndDelete(req.params.id);
  if (!adminLog)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: ADMINLOG_CONSTANT.INVALID_ADMINLOG,
    });
  return res.send({ statusCode: 200, message: "Success" });
});

async function logCurrentAdminLogState(adminLog) {
  let adminLogAudit = new AdminLogAudit({
    email: adminLog.email,
    password: adminLog.password,
  });
  await adminLogAudit.save();
}






module.exports = router;