import mongoose from 'mongoose';

//======================= Task Schema =============================
const taskSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    status: { type: String, default: 'pending' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

console.log("Task Model initialized");

export const Task = mongoose.model('Task', taskSchema);