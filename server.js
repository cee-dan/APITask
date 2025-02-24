const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config(); // Load environment variables

const app = express();
const PORT = 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'secretkey';

app.use(express.json());
app.use(cors());

// In-memory storage for users and tasks
let users = [];
let tasks = [];

// Middleware to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. Token required in format: Bearer <token>' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const verified = jwt.verify(token, SECRET_KEY);
        req.user = verified;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Welcome message
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the Task Manager API' });
});

// Register a new user with hashed password
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.json({ message: 'User registered successfully' });
});

// Login user and return JWT token
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = users.find(u => u.username === username);
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '2h' }); // Token lasts 2 hours
    res.json({ token });
});

// Create a new task (Authentication required)
app.post('/tasks', authenticateToken, (req, res) => {
    const { title, description } = req.body;
    if (!title || !description) {
        return res.status(400).json({ error: 'Title and description are required' });
    }
    
    const task = { id: tasks.length + 1, title, description, completed: false };
    tasks.push(task);
    res.json(task);
});

// Get all tasks (Authentication required)
app.get('/tasks', authenticateToken, (req, res) => {
    res.json(tasks); 
});

// Update a task by ID (Authentication required)
app.put('/tasks/:id', authenticateToken, (req, res) => {
    const { title, description, completed } = req.body;
    const task = tasks.find(t => t.id == req.params.id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    
    task.title = title || task.title;
    task.description = description || task.description;
    task.completed = completed !== undefined ? completed : task.completed;
    res.json(task);
});

// Delete a task by ID (Authentication required)
app.delete('/tasks/:id', authenticateToken, (req, res) => {
    const taskIndex = tasks.findIndex(t => t.id == req.params.id);
    if (taskIndex === -1) return res.status(404).json({ error: 'Task not found' });
    
    tasks.splice(taskIndex, 1);
    res.json({ message: 'Task deleted' });
});

// Start the server on port 3000
app.listen(PORT, '127.0.0.1', () => console.log(`Server running on http://127.0.0.1:${PORT}`));
