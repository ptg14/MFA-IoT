const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const database = require('../utils/database');

// Create controller instance
const authController = new AuthController(database);

// User registration route
router.post('/register', (req, res) => authController.registerUser(req, res));

// User login route
router.post('/login', (req, res) => authController.loginUser(req, res));

// Set pass matrix route
router.post('/setPassMatrix', (req, res) => authController.setPassMatrix(req, res));

// Verify pass matrix route
router.post('/verifyPassMatrix', (req, res) => authController.verifyPassMatrix(req, res));

// Generate token route
router.post('/generateToken', (req, res) => authController.generateToken(req, res));

// Validate token route
router.post('/validateToken', (req, res) => authController.validateToken(req, res));

// User logout route
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

module.exports = router;
