require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const User = require('./models/user'); // Replace with your actual User model
const { Parser } = require('json2csv');
let ejs = require('ejs');

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');

// Check required environment variables
if (!process.env.MONGODB_URI) {
  console.error('Error: Missing MONGODB_URI in environment variables');
  process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads')); // Serve static files from the uploads directory

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
    setupAdmin();
  })
  .catch((err) => console.error('MongoDB connection error:', err));

// Multer setup for avatar uploads
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  },
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
});

// Middleware to validate request bodies
const validateRequestBody = (requiredFields) => (req, res, next) => {
  const missingFields = requiredFields.filter((field) => !req.body[field]);
  if (missingFields.length > 0) {
    return res.status(400).json({ message: `Missing fields: ${missingFields.join(', ')}` });
  }
  next();
};

// Setup default admin
const setupAdmin = async () => {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('123456', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        status: 'active',
      });
      console.log('Default admin created (username: admin, password: 123456)');
    } else {
      console.log('Default admin already exists');
    }
  } catch (error) {
    console.error('Error setting up default admin:', error.message);
  }
};

// Routes

// Get all users
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password -resetToken -resetTokenExpiry');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Failed to retrieve users', error: err.message });
  }
});

// Get user by ID
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -resetToken -resetTokenExpiry');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to retrieve user', error: err.message });
  }
});

// Register a new user
app.post(
  '/api/register',
  upload.single('avatar'),
  validateRequestBody(['username', 'password']),
  async (req, res) => {
    const { username, email, password } = req.body;
    const avatar = req.file ? `/uploads/${req.file.filename}` : null;

    try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        username,
        email,
        password: hashedPassword,
        role: 'user',
        status: 'active',
        avatar,
      });

      await newUser.save();
      res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error registering user', error: err.message });
    }
  }
);

// Login user
app.post('/api/login', validateRequestBody(['username', 'password']), async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar || '/uploads/default-avatar.png',
        role: user.role,
        status: user.status,
      },
    });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// Upload or update avatar
app.put('/api/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const userId = req.params.id;
    const avatarPath = `/uploads/${req.file.filename}`;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.avatar = avatarPath; // Update avatar
    await user.save();

    res.json({
      message: 'Avatar updated successfully',
      user: {
        id: user._id,
        username: user.username,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    console.error('Error updating avatar:', error);
    res.status(500).json({ message: 'Failed to update avatar', error: error.message });
  }
});

// Export users to CSV
app.get('/api/export', async (req, res) => {
  try {
    const users = await User.find().select('-password -resetToken -resetTokenExpiry');
    if (users.length === 0) {
      return res.status(404).json({ message: 'No users found to export' });
    }

    const fields = ['_id', 'username', 'email', 'role', 'status', 'createdAt', 'updatedAt'];
    const opts = { fields };
    const parser = new Parser(opts);
    const csv = parser.parse(users);

    res.header('Content-Type', 'text/csv');
    res.attachment('users.csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ message: 'Error exporting users to CSV', error: err.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

app.get("/dt.html", (req, res)=>{
  return res.render("dt")
})
app.get("/Login.html", (req, res)=>{
  return res.render("Login")
} )
app.get("/register.html", (req, res)=>{
  return res.render("register")
} )

app.get("/Navigation.html", (req, res)=>{
  return res.render("Navigation")
} )

app.get("/Changepassword.html", (req, res)=>{
  return res.render("Changepassword")
} )
app.get("/Weather.html", (req, res)=>{
  return res.render("Weather")
} )

app.get("/Admin.html", (req, res)=>{
  return res.render("Admin")
} )

