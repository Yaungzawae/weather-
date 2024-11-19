const mongoose = require('mongoose');

const reserveSchema = new mongoose.Schema({
  name: { type: String, required: true }, // 保护区名称
  level: { type: String, required: true }, // 保护区级别
  type: { type: String, required: true },  // 保护区类型
  area: { type: Number, required: true },  // 保护区面积
  yearEstablished: { type: Number, required: true }, // 成立年份
  department: { type: String, required: true },  // 主管部门
  longitude: { type: Number, required: true },  // 经度
  latitude: { type: Number, required: true },   // 纬度
  protectedAnimals: { type: [String], default: [] }, // 保护动物数组
  protectedPlants: { type: [String], default: [] },  // 保护植物数组
});

module.exports = mongoose.model('Reserve', reserveSchema);
