const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const https = require('https');
const fs = require('fs');
const path = require('path');
const authRoutes = require('./routes/authRoutes');
const weatherRoutes = require('./routes/weatherRoutes');
const iotRoutes = require('./routes/iotRoutes');
const database = require('./utils/database');
const { isAuthenticated } = require('./middleware/authMiddleware');

const app = express();
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

database.connect()
    .then(() => {
        console.log('Database connected successfully');
    })
    .catch(err => {
        console.error('Database connection failed:', err);
    });

// SSL/HTTPS Configuration
const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, '../config/ssl/server.key')),
    cert: fs.readFileSync(path.join(__dirname, '../config/ssl/server.cert')),
};

app.use('/api/auth', authRoutes);
app.use('/api', isAuthenticated, weatherRoutes);  // Protect API routes
app.use('/iot', iotRoutes);

// Login and register routes (public)
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/views/register.html');
});

// Protected route - main dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/views/dashboard.html');
});

// Create HTTPS server
const httpsServer = https.createServer(sslOptions, app);

// Start HTTPS server
httpsServer.listen(HTTPS_PORT, () => {
    console.log(`HTTPS Server is running on https://0.0.0.0:${HTTPS_PORT}`);
});

// Optional: Also start HTTP server (for redirection or development)
app.listen(PORT, () => {
    console.log(`HTTP Server is running on http://0.0.0.0:${PORT}`);
});
