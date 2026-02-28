import mongoose from 'mongoose';

//======================= User Schema =============================
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

console.log("User Model initialized");

export const User = mongoose.model('User', userSchema);