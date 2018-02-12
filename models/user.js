const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true},
  password: String
});

// On save hook, encrypt password:
// before saving a model, run this function
userSchema.pre('save', function(next) {
  // get access to the user model
  const user = this;

  // generate a salt (10, callback), then run callback
  bcrypt.genSalt(10, function(error, salt) {
    if(error) { return next(error); }

    // hash (encrypt) our password using the salt
    bcrypt.hash(user.password, salt, null, function(error, hash) {
      if(error) { return next(error); }

      // overwrite plain text password with encrypted one
      user.password = hash;
      next();
    })
  })
});

// whenever we create a user object its going to have access
// to any function we define on this methods property
userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(error, isMatch) {
    if(error) {
      return callback(error);
    }
    callback(null, isMatch);
  })
};

// Create model class
const ModelClass = mongoose.model('user', userSchema);

// Export the model
module.exports = ModelClass;
