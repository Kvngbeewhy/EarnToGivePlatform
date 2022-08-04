const express = require("express");
const router = express.Router();
const {Donate} = require("../models/donate");
const _ = require("lodash");
const response = require("../service/response");
const mongoose = require ('mongoose');
mongoose.set("debug", true);



    const paystack = (request,) => {
        const MySecretKey = 'sk_test_c976139db56c8875fbdf9e5ea4713a32e9095d2f';
        //sk_test_xxxx to be replaced by your own secret key
        const donatePayment = (full_name, email, amount, mycallback) => {
            const option = {
                url : 'https://api.paystack.co/transaction/initialize',
                headers : {
                    authorization: MySecretKey,
                    'content-type': 'application/json',
                    'cache-control': 'no-cache'
               },
               full_name, email, amount,
            }
            const callback = (error, response, body)=>{
                return donatePayment(error, body);
            }
            request.post(option,callback);
        }
        const verifyPayment = (ref,mycallback) => {
            const option = {
                url : 'https://api.paystack.co/transaction/verify/' + encodeURIComponent(ref),
                headers : {
                    authorization: MySecretKey,
                    'content-type': 'application/json',
                    'cache-control': 'no-cache'
               }
            }
            const callback = (error, response, body)=>{
                return mycallback(error, body);
            }
            request(option,callback);
        }
        return {donatePayment, verifyPayment};
    }
    module.exports = paystack





module.exports = router