// server.js
require('dotenv').config(); // Load environment variables

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');


const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// ✅ Allow Netlify and local development
app.use(cors({
  origin: [
    "http://localhost:5500",           // local testing
    "http://127.0.0.1:5500",           // another local variation
    "https://chat3080.netlify.app" // replace with your real Netlify domain
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));


const transporter = nodemailer.createTransport({
  service: 'gmail', // or another email provider
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Test transporter
transporter.verify((error, success) => {
  if (error) console.log('Email transporter error:', error);
  else console.log('Server is ready to send emails');
});


// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));
 // Serve static files including index.html

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Database connection
// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});



mongoose.connection.on('disconnected', () => {
  console.log('Disconnected from MongoDB');
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['student', 'lecturer'], required: true },
  matricNumber: { type: String, unique: true, sparse: true }, // Only for students
  createdAt: { type: Date, default: Date.now }
});

// Class Schema
const classSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  joinCode: { type: String, required: true, unique: true },
  lecturerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

// Assignment Schema
const assignmentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  dueDate: { type: Date, required: true },
  classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: true },
  lecturerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

// Submission Schema
const submissionSchema = new mongoose.Schema({
  assignmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Assignment', required: true },
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  matricNumber: { type: String, required: true },
  description: { type: String },
  files: [{ 
    filename: String, 
    originalName: String, 
    path: String,
    mimetype: String 
  }],
  grade: { type: Number, min: 0, max: 100 },
  feedback: { type: String },
  submittedAt: { type: Date, default: Date.now },
  gradedAt: { type: Date }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Class = mongoose.model('Class', classSchema);
const Assignment = mongoose.model('Assignment', assignmentSchema);
const Submission = mongoose.model('Submission', submissionSchema);
const Message = mongoose.model('Message', messageSchema);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'image/jpeg', 'image/png', 'image/jpg'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOCX, and images are allowed.'), false);
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-change-in-production';

// Generate unique join code
const generateJoinCode = () => {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Lecturer authorization middleware
const requireLecturer = (req, res, next) => {
  if (req.user.role !== 'lecturer') {
    return res.status(403).json({ error: 'Lecturer access required' });
  }
  next();
};

// AUTHENTICATION ROUTES

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role, matricNumber } = req.body;
    // Strong password regex: 
  // At least 8 chars, 1 uppercase, 1 lowercase, 1 number, 
 const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z]{8,}/;

if (!strongPassword.test(password)) {
    return res.status(400).json({ 
        error: 'Password must be at least 8 characters and include: uppercase letter, lowercase letter, number)' 
    });
}
    // Validate school email
    const schoolDomain = process.env.SCHOOL_DOMAIN || 'gmail.com';
    if (!email.includes('@') || !email.endsWith(`@${schoolDomain}`)) {
      return res.status(400).json({ error: `Please use your school email address ending with @${schoolDomain}` });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      name,
      role,
      matricNumber: role === 'student' ? matricNumber : undefined
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        matricNumber: user.matricNumber
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        matricNumber: user.matricNumber
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Forgot Password Route
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: 'Email not found' });

// Generate a JWT token for this user
const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

// Determine base URL depending on environment
const baseURL = process.env.BASE_URL || 'https://chat3080.onrender.com';

// In production, set BASE_URL in your .env to your live domain like: https://yourwebsite.com

// Construct reset link
const resetLink = `${baseURL}/reset-password.html?token=${resetToken}`;

    // Send email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset',
      html: `Click <a href="${resetLink}">here</a> to reset your password. Link expires in 1 hour.`,
    });

    res.json({ message: 'Password reset link sent to your email.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});



// Get current user profile
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      email: req.user.email,
      name: req.user.name,
      role: req.user.role,
      matricNumber: req.user.matricNumber
    }
  });
});





// Reset Password Route
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Hash the new password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// CLASS MANAGEMENT ROUTES

// Create class (lecturer only)
app.post('/api/classes', authenticateToken, requireLecturer, async (req, res) => {
  try {
    const { name, description } = req.body;
    
    let joinCode;
    let codeExists = true;
    
    // Generate unique join code
    while (codeExists) {
      joinCode = generateJoinCode();
      const existingClass = await Class.findOne({ joinCode });
      if (!existingClass) {
        codeExists = false;
      }
    }

    const newClass = new Class({
      name,
      description,
      joinCode,
      lecturerId: req.user._id
    });

    await newClass.save();
    
    res.status(201).json({
      message: 'Class created successfully',
      class: newClass
    });
  } catch (error) {
    console.error('Create class error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Join class (student only)
app.post('/api/classes/join', authenticateToken, async (req, res) => {
  try {
    const { joinCode } = req.body;

    if (req.user.role !== 'student') {
      return res.status(403).json({ error: 'Only students can join classes' });
    }

    const classToJoin = await Class.findOne({ joinCode });
    if (!classToJoin) {
      return res.status(404).json({ error: 'Invalid join code' });
    }

    // Check if student is already enrolled
    if (classToJoin.students.includes(req.user._id)) {
      return res.status(400).json({ error: 'You are already enrolled in this class' });
    }

    // Add student to class
    classToJoin.students.push(req.user._id);
    await classToJoin.save();

    res.json({
      message: 'Successfully joined class',
      class: classToJoin
    });
  } catch (error) {
    console.error('Join class error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user's classes
app.get('/api/classes', authenticateToken, async (req, res) => {
  try {
    let classes;
    
    if (req.user.role === 'lecturer') {
      classes = await Class.find({ lecturerId: req.user._id })
        .populate('students', 'name email matricNumber');
    } else {
      classes = await Class.find({ students: req.user._id })
        .populate('lecturerId', 'name email');
    }

    res.json({ classes });
  } catch (error) {
    console.error('Get classes error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get specific class details
app.get('/api/classes/:classId', authenticateToken, async (req, res) => {
  try {
    const { classId } = req.params;
    
    const classData = await Class.findById(classId)
      .populate('lecturerId', 'name email')
      .populate('students', 'name email matricNumber');

    if (!classData) {
      return res.status(404).json({ error: 'Class not found' });
    }

    // Check if user has access to this class
    const hasAccess = classData.lecturerId._id.equals(req.user._id) || 
                     classData.students.some(student => student._id.equals(req.user._id));
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({ class: classData });
  } catch (error) {
    console.error('Get class details error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ASSIGNMENT ROUTES

// Create assignment (lecturer only)
app.post('/api/assignments', authenticateToken, requireLecturer, async (req, res) => {
  try {
    const { title, description, dueDate, classId } = req.body;

    // Verify lecturer owns the class
    const classData = await Class.findById(classId).populate('students', 'name email');
    if (!classData || !classData.lecturerId.equals(req.user._id)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const assignment = new Assignment({
      title,
      description,
      dueDate: new Date(dueDate),
      classId,
      lecturerId: req.user._id
    });

    await assignment.save();

    // Notify all students in the class via Socket.IO
    classData.students.forEach(student => {
      io.emit('new-assignment', {
        title: assignment.title,
        className: classData.name,
        assignmentId: assignment._id,
        studentId: student._id.toString()
      });
    });

    res.status(201).json({
      message: 'Assignment created successfully',
      assignment
    });
  } catch (error) {
    console.error('Create assignment error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get assignments for a class
app.get('/api/classes/:classId/assignments', authenticateToken, async (req, res) => {
  try {
    const { classId } = req.params;

    // Verify user has access to the class
    const classData = await Class.findById(classId);
    if (!classData) {
      return res.status(404).json({ error: 'Class not found' });
    }

    const hasAccess = classData.lecturerId.equals(req.user._id) || 
                     classData.students.includes(req.user._id);
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const assignments = await Assignment.find({ classId })
      .populate('lecturerId', 'name email')
      .sort({ createdAt: -1 });

    // For each assignment, add submission info if user is a student
    const assignmentsWithSubmissions = await Promise.all(assignments.map(async (assignment) => {
      const assignmentObj = assignment.toObject();
      
      if (req.user.role === 'student') {
        const submission = await Submission.findOne({
          assignmentId: assignment._id,
          studentId: req.user._id
        });
        
        assignmentObj.submission = submission;
      }
      
      return assignmentObj;
    }));

    res.json({ assignments: assignmentsWithSubmissions });
  } catch (error) {
    console.error('Get assignments error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Submit assignment (student only)
app.post('/api/assignments/:assignmentId/submit', 
  authenticateToken, 
  upload.array('files', 5), 
  async (req, res) => {
    try {
      const { assignmentId } = req.params;
      const { description, matricNumber } = req.body;

      if (req.user.role !== 'student') {
        return res.status(403).json({ error: 'Only students can submit assignments' });
      }

      // Verify assignment exists and student has access
      const assignment = await Assignment.findById(assignmentId).populate({
        path: 'classId',
        select: 'students lecturerId name'
      });

      if (!assignment) {
        return res.status(404).json({ error: 'Assignment not found' });
      }

      if (!assignment.classId.students.includes(req.user._id)) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // Check if already submitted
      const existingSubmission = await Submission.findOne({
        assignmentId,
        studentId: req.user._id
      });

      if (existingSubmission) {
        return res.status(400).json({ error: 'Assignment already submitted' });
      }

      // Process uploaded files
      const files = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        path: file.path,
        mimetype: file.mimetype
      }));

      const submission = new Submission({
        assignmentId,
        studentId: req.user._id,
        matricNumber,
        description,
        files
      });

      await submission.save();

      // Notify lecturer about new submission
      io.emit('new-submission', {
        assignmentTitle: assignment.title,
        studentName: req.user.name,
        lecturerId: assignment.classId.lecturerId.toString(),
        submissionId: submission._id
      });

      res.status(201).json({
        message: 'Assignment submitted successfully',
        submission
      });
    } catch (error) {
      console.error('Submit assignment error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Get submissions for an assignment (lecturer only)
app.get('/api/assignments/:assignmentId/submissions', authenticateToken, requireLecturer, async (req, res) => {
  try {
    const { assignmentId } = req.params;

    // Verify lecturer owns the assignment
    const assignment = await Assignment.findById(assignmentId);
    if (!assignment || !assignment.lecturerId.equals(req.user._id)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const submissions = await Submission.find({ assignmentId })
      .populate('studentId', 'name email matricNumber')
      .sort({ submittedAt: -1 });

    res.json({ submissions });
  } catch (error) {
    console.error('Get submissions error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Grade submission (lecturer only)
app.put('/api/submissions/:submissionId/grade', authenticateToken, requireLecturer, async (req, res) => {
  try {
    const { submissionId } = req.params;
    const { grade, feedback } = req.body;

    const submission = await Submission.findById(submissionId)
      .populate({
        path: 'assignmentId',
        select: 'lecturerId title'
      })
      .populate('studentId', 'name email');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    // Verify lecturer owns the assignment
    if (!submission.assignmentId.lecturerId.equals(req.user._id)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    submission.grade = grade;
    submission.feedback = feedback;
    submission.gradedAt = new Date();

    await submission.save();

    // Notify student about grade
    io.emit('assignment-graded', {
      assignmentTitle: submission.assignmentId.title,
      grade: grade,
      feedback: feedback,
      studentId: submission.studentId._id.toString()
    });

    res.json({
      message: 'Submission graded successfully',
      submission
    });
  } catch (error) {
    console.error('Grade submission error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Download submission file
app.get('/api/files/:filename', authenticateToken, async (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(__dirname, 'uploads', filename);

    // Verify file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Additional security: verify user has access to this file
    // Find submission that contains this file
    const submission = await Submission.findOne({
      'files.filename': filename
    }).populate({
      path: 'assignmentId',
      populate: {
        path: 'classId',
        select: 'lecturerId students'
      }
    });

    if (!submission) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Check if user has access (lecturer of the class or the student who submitted)
    const classData = submission.assignmentId.classId;
    const hasAccess = classData.lecturerId.equals(req.user._id) || 
                     submission.studentId.equals(req.user._id);

    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get original filename
    const fileInfo = submission.files.find(f => f.filename === filename);
    const originalName = fileInfo ? fileInfo.originalName : filename;

    res.download(filePath, originalName);
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Alternative route for file download with token in URL (for direct links)
app.get('/api/download/:filename/:token', async (req, res) => {
  try {
    const { filename, token } = req.params;
    
    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const filePath = path.join(__dirname, 'uploads', filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Find submission and verify access (same as above)
    const submission = await Submission.findOne({
      'files.filename': filename
    }).populate({
      path: 'assignmentId',
      populate: {
        path: 'classId',
        select: 'lecturerId students'
      }
    });

    if (!submission) {
      return res.status(404).json({ error: 'File not found' });
    }

    const classData = submission.assignmentId.classId;
    const hasAccess = classData.lecturerId.equals(user._id) || 
                     submission.studentId.equals(user._id);

    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const fileInfo = submission.files.find(f => f.filename === filename);
    const originalName = fileInfo ? fileInfo.originalName : filename;

    res.download(filePath, originalName);
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ error: 'Invalid or expired download link' });
  }
});

// MESSAGING ROUTES

// Get messages for a class
app.get('/api/classes/:classId/messages', authenticateToken, async (req, res) => {
  try {
    const { classId } = req.params;

    // Verify user has access to the class
    const classData = await Class.findById(classId);
    if (!classData) {
      return res.status(404).json({ error: 'Class not found' });
    }

    const hasAccess = classData.lecturerId.equals(req.user._id) || 
                     classData.students.includes(req.user._id);
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const messages = await Message.find({ classId })
      .populate('senderId', 'name email role')
      .sort({ timestamp: 1 })
      .limit(50); // Limit to last 50 messages

    res.json({ messages });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: error.message });
  }
});

// SOCKET.IO FOR REAL-TIME MESSAGING
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Join class room
  socket.on('join-class', (classId) => {
    socket.join(classId);
    console.log(`User ${socket.id} joined class ${classId}`);
  });

  // Send message
  socket.on('send-message', async (data) => {
    try {
      const { classId, message, userId } = data;

      // Verify user has access to class
      const user = await User.findById(userId);
      const classData = await Class.findById(classId);
      
      if (!user || !classData) {
        return;
      }

      const hasAccess = classData.lecturerId.equals(userId) || 
                       classData.students.includes(userId);
      
      if (!hasAccess) {
        return;
      }

      // Save message to database
      const newMessage = new Message({
        classId,
        senderId: userId,
        message
      });

      await newMessage.save();
      await newMessage.populate('senderId', 'name email role');

      // Broadcast message to class room
      io.to(classId).emit('new-message', newMessage);
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
  }
  console.error('Error:', error);
  res.status(500).json({ error: error.message });
});

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'Chat3080.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);

  if (process.env.RENDER) {
    console.log(`🌍 Live app: https://${process.env.RENDER_EXTERNAL_HOSTNAME}`);
  } else {
    console.log(`📱 Access your app locally at: http://localhost:${PORT}`);
  }
});

module.exports = app;
