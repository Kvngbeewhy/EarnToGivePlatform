const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const config = require("config");

const TabSchema = new mongoose.Schema(
  {
    id: String,
    userId: [
      { type: mongoose.Schema.Types.ObjectId, ref: "userId", required: false },
    ],
    name: String,
    description: String,
    dataPoints: [
      {
        dataType: String,
        label: String,
        descriptions: String,
        placeholder: String,
        options: [String],
      },
    ],
  },
  { timestamps: true },
);

const Tab = mongoose.model("Tab", TabSchema);

const tabAuditSchema = new mongoose.Schema({
  id: String,
  userId: String,
  name: String,
  descriptions: String,
  dataPoints: [
    {
      dataType: String,
      label: String,
      description: String,
      placeholder: String,
      options: [String],
    },
  ],
});

const TabAudit = mongoose.model("Tab Audit", tabAuditSchema);

function validateTabPost(tab) {
  const schema = {
    name: Joi.string().min(2).max(200),
    options: Joi.number().integer(),
    dataPoints: Joi.Array().items(),
    label: Joi.string(),
    description: Joi.string().max(500),
  };
  return Joi.validate(tab, schema);
}

function validateTabPut(tab) {
  const schema = {
    name: Joi.string().required(),
  };
  return Joi.validate(tab, schema);
}
module.exports.Tab = Tab;
module.exports.TabAudit = TabAudit;
module.exports.validateTabPost = validateTabPost;
module.exports.validateTabPut = validateTabPut;
