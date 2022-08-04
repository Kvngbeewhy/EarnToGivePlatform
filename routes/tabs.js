const config = require("config");
const mongoose = require("mongoose");
const response = require("../service/response");
const express = require("express");
const router = express.Router();
const {
  Tab,
  TabAudit,
  validateTabPost,
  validateTabPut,
} = require("../models/tabs");
const { User } = require("../models/user");
const { userAuth } = require("../middleware/auth");
const _ = require("lodash");
const { TAB_CONSTANTS, AUTH_CONSTANTS } = require("../config/constant.js");

mongoose.set("debug", true);

///Get all Tabs
router.get("/", async (req, res) => {
  let tabList = await Tab.find({}, "-_id");
  return res.send({
    tabList,
  }) 
});

router.get("/new", async (req, res) => {
  let tabList = await Tab.find({}, "-_id");
  return res.status(200).send({
    statusCode: 200,
    message: TAB_CONSTANTS.GET_UPDATE,
    data: tabList,
  });
});


router.post("/", async (req, res) => {
  //Add dataPoint into Array
  let dataPoints = [];
  for (let datp = 0; datp < req.body.dataPoints.length; datp++) {
    const element = req.body.dataPoints[datp];
    if (element.label === "ECOG_SCORE") {
      req.body.dataPoints.dataType = "selection";
      dataPoints.push(element);
    }
    if (element.label === "ECOG_HB_LEVEL") {
      req.body.dataPoints.dataType = "text";
      dataPoints.push(element);
    }
  }

  const { name, description } = req.body;

  try {
    tab = new Tab({
      name,
      description,
      dataPoints,
    });

    // save user to db
    await tab.save();
  } catch (err) {
    console.error(err.message);
    return response.error(res, err.message, 500);
  }
});

router.put("/:tabId", async (req, res) => {
  const { error } = validateTabPut(req.body);
  if (error)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: error.details[0].message,
    });
    
  var tab = Tab.findOne(req.params.id);
  if (!tab)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: TAB_CONSTANTS.INVALID_TAB,
    });
  await logCurrentTabState(tab);

  const { name } = req.body;
  try {
    tab = new Tab({
      name,
    });

    // save user to db
    await tab.update();
  } catch (err) {
    console.error(err.message);
    return response.error(res, err.message, 500);
  }

  let resp = _.pick(tab, ["name", "description"]);

  res.send({ statusCode: 200, message: "Success", data: resp });
});

router.delete("/:id", async (req, res) => {
  console.log(req.body);
  var tab = Tab.findByIdAndDelete(req.params.id);
  if (!tab)
    return res.status(400).send({
      statusCode: 400,
      message: "Failure",
      data: TAB_CONSTANTS.INVALID_TAB,
    });
  return res.send({ statusCode: 200, message: "Success" });
});

async function logCurrentTabState(tab) {
  let tabAudit = new TabAudit({
    name: tab.name,
    description: tab.description,
  });
  await tabAudit.save();
}
module.exports = router;
