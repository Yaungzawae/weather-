const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  status: { type: String, default: 'active' },
  avatar: { type: String },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
