const { User } = require("../models/user");
const bcrypt = require("bcryptjs");

module.exports = async () => {
  const userExists = await User.findOne({
    email: "godmode@falcon.com",
    phone: "0123456789",
    status: "active",
  });

  if (!userExists) {
    const password = "12345678";
    const user = await User.create({
      firstName: "Test",
      lastName: "tester",
      email: "godmode@falcon.com",
      phone: "0123456789",
      password,
      status: "active",
      isVerified: true,
    });

    //create salt for user password hash
    const salt = await bcrypt.genSalt(10);

    //replace user password with the hashed password
    user.password = await bcrypt.hash(password, salt);

    // save user to db
    await user.save();
    console.log('seed user "admin" created...');
  }
  console.log(":-)");
}
