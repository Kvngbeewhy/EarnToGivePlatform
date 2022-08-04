const Joi = require("joi");
const mongoose = require("mongoose");

const AdminLogSchema = new mongoose.Schema(
    {
        adminLogId: String,
        email: String,
        password: String,
        createdby: String,
        lastmodifiedby: String,
        creationDate: {
          type: Date,
          default: () => {
            return new Date();
          },
        },
        insertDate: {
          type: Number,
          default: () => {
            return Math.round(new Date() / 1000);
          },
        },
      },
      { timestamps: true },

);
const AdminLog = mongoose.model("Adminlog", AdminLogSchema);

const adminLogAuditSchema = new mongoose.Schema(
  {
      adminLogId: String,
      email: String,
      password: String,
      lastmodified: String,
      creationDate: {
        type: Date,
        default: () => {
          return new Date();
        },
      },
      insertDate: {
        type: Number,
        default: () => {
          return Math.round(new Date() / 1000);
        },
      },
    },
    { timestamps: true },
);
  
const AdminLogAudit = mongoose.model("Adminlog Audit", adminLogAuditSchema);

function validateAdminLogPost(adminLog){
  const schema = { 
      email: Joi.string().min(5).max(100).required(),
      password: Joi.string().min(6).max(20).required(),
      createdby: Joi.string().required(),
  };
  return Joi.validate(adminLog, schema)
}


function validateAdminLogPut(adminLog){
  const schema = { 
      email: Joi.string().min(5).max(100).required(),
      password: Joi.string().min(6).max(20).required(),
      lastmodifiedby: Joi.string().required(),
  };
  return Joi.validate(adminLog, schema)
}

module.exports.AdminLog = AdminLog;
module.exports.validateAdminLogPut = validateAdminLogPut;
module.exports.validateAdminLogPost = validateAdminLogPost;
module.exports.AdminLogAudit = AdminLogAudit;
