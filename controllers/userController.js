const { User } = require("../models/userModel.js");

// Here the user with same email is found and returned
module.exports.getUserByEmail=(request)=> {
  return User.findOne({
    email: request.body.email,
  });
}

// Here the user with same id is found and returned
module.exports.getUserById=(userID)=> {
  return User.findById(userID).select("_id");
}

module.exports.getAll = ()=>{
  return User.find({})
}