import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import morgan from 'morgan';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Models
import { User } from './models/User.js';
import { Task } from './models/Task.js';

// Middleware
import { verifyToken, isAdmin } from './middleware/auth.js';

//==================//========================
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('views'));
const port = process.env.PORT || 3000;
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('dev'));
app.use(morgan('combined', { stream: accessLogStream })); 

//======================= connection to the DB =============================
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
      console.log('Connected to MongoDB Atlas (status code: 200)');
  })
  .catch((err) => {
      console.error("Failed to connect to MongoDB (status code: 500)", err.message);
  });

//================================================ API logic for User Registration ====================================================
app.post('/api/v1/auth/register', async (req, res) => {
    console.log("Register API hit");
    try {
        const { name, email, password, role } = req.body;
        
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create new user
        const newUser = new User({ 
            name: name, 
            email: email, 
            password: hashedPassword, 
            role: role || 'user' 
        });
        
        await newUser.save();
        console.log("New user credential saved:", newUser.email);
        res.status(201).json({ success: true, message: "User registered successfully" });
    } catch (err) {
        console.error("Error in saving user:", err.message);
        res.status(400).json({ success: false, error: "Email already exists or invalid data" });
    }
});

//================================================== API login =========================================================
app.post('/api/v1/auth/login', async (req, res) => {
    console.log("Login API hit");
    const data = req.body;
    
    try {
        const user = await User.findOne({ email: data.email });
        if (!user) {
            console.log('User not found');
            return res.status(401).json({ success: false, error: "Invalid credentials" });
        }
        
        const isMatch = await bcrypt.compare(data.password, user.password);
        if (isMatch === false) {
            console.log('Incorrect password');
            return res.status(401).json({ success: false, error: "Invalid credentials" });
        }
        
        console.log('User found, login successful');
        
        // Token generation
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        res.cookie('token', token, { 
            httpOnly: true, // prevents client-side JS access
            sameSite: 'strict'
        });
        console.log("cookie sends");
        
        return res.status(200).json({ success: true, token, role: user.role });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
});

//=================================== API FOR LOGOUT ===========================================
app.post('/api/v1/auth/logout', (req, res) => {
    console.log("Logout API hit");
    res.clearCookie('token').json({ success: true, message: "Logged out successfully" });
});

//=================================== API FOR TASKS (CRUD) ===========================================

// CREATE Task
app.post('/api/v1/tasks', verifyToken, async (req, res) => {
    console.log("Create Task API hit by user:", req.user.id);
    try {
        const task = new Task({ ...req.body, userId: req.user.id });
        await task.save();
        res.status(201).json(task);
    } catch (err) {
        res.status(500).json({ error: "Failed to create task" });
    }
});

// READ Tasks (Users see their own, Admins logic handled here)
app.get('/api/v1/tasks', verifyToken, async (req, res) => {
    try {
        const query = req.user.role === 'admin' ? {} : { userId: req.user.id };
        const tasks = await Task.find(query);
        res.json(tasks);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch tasks" });
    }
});

// UPDATE Task
app.put('/api/v1/tasks/:id', verifyToken, async (req, res) => {
    try {
        const task = await Task.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id }, 
            req.body, 
            { new: true }
        );
        if (!task) return res.status(404).json({ error: "Task not found or unauthorized" });
        res.json(task);
    } catch (err) {
        res.status(500).json({ error: "Failed to update task" });
    }
});

// DELETE Task
app.delete('/api/v1/tasks/:id', verifyToken, async (req, res) => {
    try {
        const task = await Task.findOneAndDelete({ 
            _id: req.params.id, 
            userId: req.user.id 
        });

        if (!task) {
            return res.status(404).json({ error: "Task not found or unauthorized" });
        }
        console.log("Task deleted");
        res.json({ message: "Task deleted successfully" });
    } catch (err) {
        console.error("Delete Error:", err.message);
        res.status(500).json({ error: "Failed to delete task" });
    }
});

//=================================== ADMIN EXCLUSIVE ROUTE ===========================================
app.delete('/api/v1/admin/tasks/:id', verifyToken, isAdmin, async (req, res) => {
    console.log("Admin Force Delete API hit");
    try {
        const task = await Task.findByIdAndDelete(req.params.id);
        if (!task) return res.status(404).json({ error: "Task not found" });
        
        res.json({ message: "Task force-deleted by admin" });
    } catch (err) {
        res.status(500).json({ error: "Admin deletion failed" });
    }
});

//=====================================================================================================

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});