const mongoose = require('mongoose');

const userBehaviorSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', // Referencing the User model
    required: true
  },
  action: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  additionalData: { 
    type: Object, 
    default: {} 
  }
});

// Export the UserBehavior model
const UserBehavior = mongoose.model('UserBehavior', userBehaviorSchema);
module.exports = UserBehavior;
