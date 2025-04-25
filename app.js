require('dotenv').config();
const express = require('express');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns');
const { promisify } = require('util');
const { exec } = require('child_process');
const dnsPromises = dns.promises;
const tls = require('tls');
const url = require('url');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const csrf = require('csurf');
const nodemailer = require('nodemailer');
const session = require('express-session');
const User = require('./models/User');
const { protect, generateToken } = require('./middleware/auth');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const hashUtils = require('./utils/hashUtils');
const util = require('util');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const FileScanner = require('./utils/fileScanner');
const FileType = require('file-type');
const fileUpload = require('express-fileupload');

const execPromise = util.promisify(exec);

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    lastModified: false,
    maxAge: 0,
    cacheControl: false
}));

// Session configuration
app.use(session({
    secret: process.env.JWT_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// CSRF protection middleware
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
});

// Apply CSRF protection to all routes except file upload and API routes
app.use((req, res, next) => {
    if (req.path === '/scan-file' || req.path.startsWith('/api/')) {
        return next();
    }
    csrfProtection(req, res, next);
});

// Add CSRF token to all responses
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken && req.csrfToken();
    next();
});

// Error handler for CSRF and other errors
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        if (req.xhr || req.headers.accept.includes('application/json')) {
        res.status(403).json({
                error: 'Invalid CSRF token',
                details: 'Please refresh the page and try again.'
        });
    } else {
            res.status(403).render('error', {
                error: 'Invalid CSRF token. Please refresh the page and try again.'
            });
        }
    } else {
        console.error('Server Error:', err);
        res.status(500).json({
            error: 'Internal Server Error',
            details: err.message
        });
    }
});

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/url-analyzer?directConnection=true', {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('MongoDB Connected Successfully');
    // Start the server only after MongoDB connects
    const server = app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
        console.log(`Visit http://localhost:${PORT} to access the application`);
    }).on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`Port ${PORT} is already in use. Please try these solutions:`);
            console.error('1. Stop any other servers running on this port');
            console.error('2. Choose a different port by setting the PORT environment variable');
            console.error('3. Wait a few seconds and try again');
        } else {
            console.error('Server error:', err);
        }
        process.exit(1);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
        console.log('SIGTERM signal received: closing HTTP server');
        server.close(() => {
            console.log('HTTP server closed');
            process.exit(0);
        });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
        console.error('Uncaught Exception:', err);
        server.close(() => {
            process.exit(1);
        });
    });
})
.catch(err => {
    console.error('MongoDB Connection Error:', err.message);
    console.log('\nTroubleshooting steps:');
    console.log('1. Make sure MongoDB is installed');
    console.log('2. Open MongoDB Compass and try connecting to: mongodb://localhost:27017');
    console.log('3. If Compass cannot connect, try these steps:');
    console.log('   a. Open Services (services.msc)');
    console.log('   b. Find "MongoDB" service');
    console.log('   c. Right-click and select "Start"');
    console.log('4. Restart this application');
});

// Simple session middleware (for demo purposes)
const sessions = new Map();

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Authentication middleware
const authenticate = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// Passport config
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3001/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
            user = await User.create({
                email: profile.emails[0].value,
                password: crypto.randomBytes(16).toString('hex')
            });
        }
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3001/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
            user = await User.create({
                email: profile.emails[0].value,
                password: crypto.randomBytes(16).toString('hex')
            });
        }
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Social login routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    }
);

app.get('/auth/github',
    passport.authenticate('github', { scope: ['user:email'] })
);

app.get('/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    }
);

// Web Routes
app.get('/', (req, res) => {
    console.log('Session:', req.session);
    console.log('User:', req.user);
    console.log('Is Authenticated:', req.isAuthenticated());
    res.render('index', { 
        user: req.user, 
        error: null,
        registered: req.query.registered === 'true',
        csrfToken: req.csrfToken() 
    });
});

// Terms and Conditions Route
app.get('/terms', (req, res) => {
    res.render('terms', { user: req.user });
});

app.get('/login', (req, res) => {
    res.render('login', { error: null, csrfToken: req.csrfToken() });
});

// Add forgot password routes
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: null, success: null, csrfToken: req.csrfToken() });
});

// Forgot password route - handle both web and API requests
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            // Check if it's an API request
            if (req.headers['content-type'] === 'application/json') {
                return res.status(404).json({
                    success: false,
                    message: 'No account found with that email address'
                });
            }
            return res.render('forgot-password', {
                error: 'No account found with that email address',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send email
        const resetUrl = `http://${req.headers.host}/reset-password/${resetToken}`;
        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset Request',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                Please click on the following link, or paste this into your browser to complete the process:\n\n
                ${resetUrl}\n\n
                If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        await transporter.sendMail(mailOptions);

        // Check if it's an API request
        if (req.headers['content-type'] === 'application/json') {
            return res.json({
                success: true,
                message: 'Password reset email sent'
            });
        }

        res.render('forgot-password', {
            error: null,
            success: 'An email has been sent with further instructions.',
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        // Check if it's an API request
        if (req.headers['content-type'] === 'application/json') {
            return res.status(500).json({
                success: false,
                message: 'Error in forgot password process'
            });
        }
        res.render('forgot-password', {
            error: 'An error occurred. Please try again later.',
            success: null,
            csrfToken: req.csrfToken()
        });
    }
});

// Add reset password routes
app.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('forgot-password', {
                error: 'Password reset token is invalid or has expired.',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        res.render('reset-password', {
            token: req.params.token,
            error: null,
            success: null,
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.render('forgot-password', {
            error: 'An error occurred. Please try again later.',
            success: null,
            csrfToken: req.csrfToken()
        });
    }
});

// Reset password route - handle both web and API requests
app.post('/reset-password/:token', async (req, res) => {
    try {
        const { password, confirmPassword } = req.body;

        // For API requests, we don't need to check confirmPassword
        if (!req.headers['content-type']?.includes('application/json') && password !== confirmPassword) {
            return res.render('reset-password', {
                token: req.params.token,
                error: 'Passwords do not match.',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            // Check if it's an API request
            if (req.headers['content-type']?.includes('application/json')) {
            return res.status(400).json({
                success: false,
                    message: 'Password reset token is invalid or has expired'
                });
            }
            return res.render('forgot-password', {
                error: 'Password reset token is invalid or has expired.',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        // Set new password
        user.password = password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        // Send confirmation email
        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Your password has been changed',
            text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
        };

        await transporter.sendMail(mailOptions);

        // Check if it's an API request
        if (req.headers['content-type']?.includes('application/json')) {
            return res.json({
                success: true,
                message: 'Password has been reset successfully'
            });
        }

        res.render('login', {
            error: null,
            success: 'Your password has been changed successfully. Please login with your new password.',
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Reset password error:', error);
        // Check if it's an API request
        if (req.headers['content-type']?.includes('application/json')) {
            return res.status(500).json({
                success: false,
                message: 'Error in resetting password'
            });
        }
        res.render('reset-password', {
            token: req.params.token,
            error: 'An error occurred while resetting your password.',
            success: null,
            csrfToken: req.csrfToken()
        });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password, terms } = req.body;

        // Check terms agreement
        if (!terms) {
            return res.render('login', { 
                error: 'You must agree to the Terms and Conditions',
                csrfToken: req.csrfToken() 
            });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.render('login', { 
                error: 'Invalid credentials', 
                csrfToken: req.csrfToken() 
            });
        }

        // Check password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.render('login', { 
                error: 'Invalid credentials', 
                csrfToken: req.csrfToken() 
            });
        }

        // Use Passport's login method
        req.login(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return res.render('login', { 
                    error: 'An error occurred during login', 
                    csrfToken: req.csrfToken() 
                });
            }
            // Redirect to home page after successful login
            res.redirect('/');
        });
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { 
            error: 'An error occurred during login', 
            csrfToken: req.csrfToken() 
        });
    }
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, csrfToken: req.csrfToken() });
});

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate email
        if (!email || !email.includes('@')) {
            return res.render('register', { 
                error: 'Please provide a valid email address',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        // Password validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.render('register', {
                error: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render('register', {
                error: 'This email is already registered. Please try logging in instead.',
                success: null,
                csrfToken: req.csrfToken()
            });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email,
            password: hashedPassword
        });
        await user.save();

        // Log the user in after registration
        req.login(user, (err) => {
            if (err) {
                return res.render('register', {
                    error: 'Registration successful but could not log in automatically. Please log in manually.',
                    success: null,
                    csrfToken: req.csrfToken()
                });
            }
            res.redirect('/?registered=true');
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', {
            error: 'An error occurred during registration. Please try again.',
            success: null,
            csrfToken: req.csrfToken()
        });
    }
});

app.get('/logout', (req, res) => {
    // Clear the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        // Clear the session cookie
        res.clearCookie('connect.sid');
        // Redirect to home page
        res.redirect('/');
    });
});

// Protected web routes
app.post('/analyze', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({
                error: 'Please enter a URL to analyze'
            });
        }

        const results = await analyzeUrl(url);
        
        // Save to search history only if user is logged in
        if (req.cookies.sessionId && sessions.has(req.cookies.sessionId)) {
            const user = sessions.get(req.cookies.sessionId);
            const searchHistory = new SearchHistory({
                userId: user.userId,
                url: results.url,
                severity: results.severity,
                analysis: results.analysis
            });
            await searchHistory.save();
        }
        
        // Render the results page with the analysis data
        res.render('results', {
            user: req.cookies.sessionId ? sessions.get(req.cookies.sessionId) : null,
            results: results,
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({
            error: error.message
        });
    }
});

// Search History Schema
const searchHistorySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    url: {
        type: String,
        required: true
    },
    severity: {
        type: String,
        required: true
    },
    analysis: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const SearchHistory = mongoose.model('SearchHistory', searchHistorySchema);

// Dashboard Route
app.get('/dashboard', authenticate, async (req, res) => {
    try {
        const searchHistory = await SearchHistory.find({ userId: req.user.userId })
            .sort({ timestamp: -1 })
            .limit(10);
        
        res.render('dashboard', { 
            user: req.user,
            searchHistory,
            error: null
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.render('dashboard', { 
            user: req.user,
            searchHistory: [],
            error: 'Failed to load search history'
        });
    }
});

// Function to check SSL certificate
async function checkSSL(hostname) {
    return new Promise((resolve) => {
        try {
            const socket = tls.connect(443, hostname, {
                timeout: 3000,
                rejectUnauthorized: false // Allow self-signed certificates for analysis
            }, () => {
                const certificate = socket.getPeerCertificate();
                socket.end();
                resolve({
                    secure: socket.authorized,
                    issuer: certificate.issuer,
                    validFrom: new Date(certificate.valid_from).toLocaleDateString(),
                    validTo: new Date(certificate.valid_to).toLocaleDateString(),
                    protocol: socket.getProtocol()
                });
            });

            socket.on('error', (error) => {
                resolve({
                    secure: false,
                    error: error.message
                });
            });
        } catch (error) {
            resolve({
                secure: false,
                error: 'Failed to establish SSL connection'
            });
        }
    });
}

// Function to check DNS records
async function checkDNS(hostname) {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            resolve({
                status: 'error',
                error: 'DNS lookup timeout'
            });
        }, 3000);

        dns.resolve(hostname, 'ANY', (err, records) => {
            clearTimeout(timeout);
            if (err) {
                resolve({
                    status: 'error',
                    error: err.message
                });
            } else {
                resolve({
                    status: 'success',
                    records: records
                });
            }
        });
    });
}

// Function to check for common malware patterns
function checkMalwarePatterns(content) {
    const malwarePatterns = {
        shellcode: /(%u[A-F0-9]{4}|\\u[A-F0-9]{4}|\\x[A-F0-9]{2}){10,}/i,
        iframeInjection: /<iframe.*?src=.*?(display:\s*none|height:\s*0|width:\s*0).*?>/i,
        evalExecution: /eval\s*\(.*?(base64|fromCharCode|escape|unescape).*?\)/i,
        suspiciousRedirect: /(window\.location|document\.location|location\.href|location\.replace)\s*=\s*["'].*?["']/i,
        encodedScript: /(base64_decode|str_rot13|gzinflate|gzuncompress|eval|assert|passthru)\s*\(/i,
        obfuscatedJS: /(\w+)\s*=\s*[\[{]\s*["'\\]+.*?["'\\]+\s*[}\]]\s*;.*?\1\s*\(/i,
        maliciousFiles: /\.(exe|dll|bat|sh|cmd|scr|ps1|vbs|hta|jar|msi|com|pif)$/i,
        cryptoMining: /(coinhive|cryptoloot|webminepool|cryptonight|minero|coinimp)/i,
        dataExfiltration: /(document\.cookie|localStorage|sessionStorage).*(send|post|fetch|ajax|xhr)/i,
        sqlInjection: /(\b(union|select|insert|update|delete|drop|alter)\b.*?(\b(from|into|table)\b))/i,
        xssPatterns: /(<script.*?>.*?(<\/script>)?|javascript:.*?|onload=.*?|onerror=.*?)/i,
        phpShells: /(c99|r57|shell|symlink|b374k|weevely|phpshell)/i,
        suspiciousParams: /\?(cmd|exec|system|passthru|eval|assert|shell|run|script)/i,
        backdoorPatterns: /(backdoor|rootkit|trojan|keylogger|spyware|botnet|RAT)/i,
        sensitiveFiles: /\/(\.git|\.env|\.config|\.ssh|\.htpasswd|wp-config\.php|config\.php|database\.yml)/i
    };

    const detections = {};
    let totalScore = 0;

    for (const [pattern, regex] of Object.entries(malwarePatterns)) {
        const matches = (content.match(regex) || []).length;
        if (matches > 0) {
            detections[pattern] = matches;
            totalScore += matches * 10; // Each match adds 10 points to risk score
        }
    }

    return { detections, score: Math.min(totalScore, 100) };
}

// Function to analyze network behavior
async function analyzeNetworkBehavior(hostname) {
    const commonMalwarePorts = [
        25,    // SMTP - spam
        445,   // SMB - worms
        3389,  // RDP - unauthorized access
        4444   // Metasploit
    ];

    const portChecks = commonMalwarePorts.map(port => {
        return new Promise(resolve => {
            const socket = new net.Socket();
            socket.setTimeout(500);

            socket.on('connect', () => {
                socket.destroy();
                resolve({ port, open: true });
            });

            socket.on('error', () => {
                resolve({ port, open: false });
            });

            socket.on('timeout', () => {
                socket.destroy();
                resolve({ port, open: false });
            });

            socket.connect(port, hostname);
        });
    });

    const results = await Promise.all(portChecks);
    const openPorts = results.filter(r => r.open).map(r => r.port);
    
    return {
        openPorts,
        suspiciousPortsFound: openPorts.length > 0,
        riskScore: openPorts.length * 15
    };
}

// Function to analyze URL structure
function analyzeUrlStructure(urlString) {
    const url = new URL(urlString);
    const suspiciousPatterns = {
        lengthAnalysis: {
            domainTooLong: url.hostname.length > 50,
            pathTooLong: url.pathname.length > 100,
            queryTooLong: url.search.length > 200
        },
        characterAnalysis: {
            unusualCharacters: /[^\w\-\./]/.test(url.hostname),
            repeatingCharacters: /([\w\-])\1{4,}/.test(url.hostname),
            numericalDomain: /^\d+$/.test(url.hostname.split('.')[0])
        },
        structureAnalysis: {
            tooManySubdomains: url.hostname.split('.').length > 4,
            tooManyParameters: url.search.split('&').length > 10,
            baseEncoding: /base64/i.test(url.search),
            suspiciousKeywords: /(admin|login|shell|backup|wp-admin|phpmyadmin)/i.test(url.pathname)
        }
    };

    let riskScore = 0;
    const riskFactors = [];

    // Length analysis
    if (suspiciousPatterns.lengthAnalysis.domainTooLong) {
        riskScore += 10;
        riskFactors.push("Unusually long domain name");
    }
    if (suspiciousPatterns.lengthAnalysis.pathTooLong) {
        riskScore += 10;
        riskFactors.push("Unusually long URL path");
    }
    if (suspiciousPatterns.lengthAnalysis.queryTooLong) {
        riskScore += 10;
        riskFactors.push("Unusually long query string");
    }

    // Character analysis
    if (suspiciousPatterns.characterAnalysis.unusualCharacters) {
        riskScore += 15;
        riskFactors.push("Unusual characters in domain");
    }
    if (suspiciousPatterns.characterAnalysis.repeatingCharacters) {
        riskScore += 15;
        riskFactors.push("Suspicious repeating characters");
    }
    if (suspiciousPatterns.characterAnalysis.numericalDomain) {
        riskScore += 10;
        riskFactors.push("Numerical-only domain");
    }

    // Structure analysis
    if (suspiciousPatterns.structureAnalysis.tooManySubdomains) {
        riskScore += 15;
        riskFactors.push("Excessive number of subdomains");
    }
    if (suspiciousPatterns.structureAnalysis.tooManyParameters) {
        riskScore += 10;
        riskFactors.push("Excessive number of URL parameters");
    }
    if (suspiciousPatterns.structureAnalysis.baseEncoding) {
        riskScore += 20;
        riskFactors.push("Base64 encoding detected in URL");
    }
    if (suspiciousPatterns.structureAnalysis.suspiciousKeywords) {
        riskScore += 15;
        riskFactors.push("Suspicious keywords in URL");
    }

    return {
        riskScore: Math.min(riskScore, 100),
        riskFactors,
        analysis: suspiciousPatterns
    };
}

// Function to analyze page content
async function analyzePage(urlString) {
    try {
        const response = await axios.get(urlString, { 
            timeout: 5000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            },
            validateStatus: false,
            maxRedirects: 3
        });

        if (response.status !== 200) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const $ = cheerio.load(response.data);
        
        // Extract links
        const links = new Set();
        const externalLinks = new Set();
        const suspiciousLinks = new Set();
        
        $('a').each((i, element) => {
            const href = $(element).attr('href');
            if (href && !href.startsWith('#')) {
                try {
                    const parsedUrl = new URL(href, urlString);
                    if (parsedUrl.hostname === new URL(urlString).hostname) {
                        links.add(href);
                    } else {
                        externalLinks.add(href);
                    }
                    
                    // Check for suspicious patterns in URLs
                    const suspiciousPatterns = [
                        /\.(exe|zip|rar|msi|scr|bat)$/i,
                        /^data:/i,
                        /^javascript:/i,
                        /^vbscript:/i,
                        /\b(password|login|signin|bank|account|verify|secure)\b/i
                    ];
                    
                    if (suspiciousPatterns.some(pattern => pattern.test(href))) {
                        suspiciousLinks.add(href);
                    }
                } catch (e) {
                    // Invalid URL
                }
            }
        });

        // Add enhanced content analysis
        const contentAnalysis = checkMalwarePatterns(response.data);
        
        // Check for cloaked redirects
        const redirects = response.request._redirectable._redirectCount;
        const hasMetaRefresh = $('meta[http-equiv="refresh"]').length > 0;
        
        // Check for suspicious scripts
        const scripts = [];
        $('script').each((i, elem) => {
            const src = $(elem).attr('src');
            const content = $(elem).html();
            if (src) scripts.push(src);
            if (content) {
                const scriptAnalysis = checkMalwarePatterns(content);
                if (scriptAnalysis.score > 0) {
                    contentAnalysis.score = Math.min(contentAnalysis.score + scriptAnalysis.score, 100);
                    Object.assign(contentAnalysis.detections, scriptAnalysis.detections);
                }
            }
        });

        // Check for malvertising patterns
        const adPatterns = {
            popups: /window\.open\s*\(/g,
            adIframes: /\/(ad|ads|banner|pop|click|track)\//i,
            redirectScripts: /(location|window|document)\.(replace|href|location)\s*=/
        };

        const adDetections = {};
        for (const [pattern, regex] of Object.entries(adPatterns)) {
            adDetections[pattern] = (response.data.match(regex) || []).length;
        }

        return {
            title: $('title').text().trim(),
            description: $('meta[name="description"]').attr('content'),
            links: Array.from(links).slice(0, 10),
            externalLinks: Array.from(externalLinks).slice(0, 10),
            suspiciousLinks: Array.from(suspiciousLinks),
            suspiciousPatterns: contentAnalysis.detections,
            redirects: {
                count: redirects,
                hasMetaRefresh
            },
            scripts: {
                total: scripts.length,
                external: scripts.filter(s => s && s.startsWith('http')).length
            },
            adAnalysis: adDetections,
            headers: response.headers,
            statusCode: response.status
        };
        } catch (error) {
        console.error('Page analysis error:', error);
        return {
            error: error.message,
            statusCode: error.response?.status || 500
        };
    }
}

// Main analysis function
async function analyzeUrl(urlString) {
    // Input validation
    if (!urlString) {
        throw new Error('URL is required');
    }

    // Clean and normalize URL
    try {
        // Remove whitespace
        urlString = urlString.trim();

        // Add protocol if missing
        if (!urlString.match(/^https?:\/\//i)) {
            urlString = 'http://' + urlString;
        }

        // Validate URL format
        const parsedUrl = new URL(urlString);
        const hostname = parsedUrl.hostname;

        // Initialize results object
        const results = {
            url: urlString,
            type: 'Unknown',
            severity: 'Low',
            riskScore: 0,
            analysis: '',
            indicators: [],
            ssl: null,
            contentAnalysis: null
        };

        // Perform parallel checks
        const [sslResult, pageResult, networkResult] = await Promise.all([
            checkSSL(hostname).catch(error => ({
                secure: false,
                error: error.message
            })),
            analyzePage(urlString).catch(error => ({
                error: error.message,
                redirects: { count: 0, hasMetaRefresh: false },
                scripts: { external: 0 },
                adAnalysis: {}
            })),
            analyzeNetworkBehavior(hostname).catch(error => ({
                openPorts: [],
                suspiciousPortsFound: false,
                riskScore: 0
            }))
        ]);

        // Update results with SSL information
        results.ssl = sslResult;

        // Update results with page analysis
        results.contentAnalysis = {
            redirects: pageResult.redirects || { count: 0, hasMetaRefresh: false },
            scripts: pageResult.scripts || { external: 0 },
            adAnalysis: pageResult.adAnalysis || {}
        };

        // Calculate risk score and determine severity
        let totalRiskScore = 0;

        // SSL Check contribution
        if (!sslResult.secure) {
            totalRiskScore += 30;
            results.indicators.push('Insecure SSL/TLS configuration');
        }

        // Network behavior contribution
        if (networkResult.suspiciousPortsFound) {
            totalRiskScore += networkResult.riskScore;
            results.indicators.push('Suspicious open ports detected');
        }

        // Content analysis contribution
        if (pageResult.redirects && pageResult.redirects.count > 2) {
            totalRiskScore += 10;
            results.indicators.push('Multiple redirects detected');
        }

        if (pageResult.scripts && pageResult.scripts.external > 5) {
            totalRiskScore += 15;
            results.indicators.push('High number of external scripts');
        }

        // Set final risk score
        results.riskScore = Math.min(100, totalRiskScore);

        // Determine severity
        if (results.riskScore >= 70) {
            results.severity = 'High';
            results.type = 'Potentially Malicious';
        } else if (results.riskScore >= 40) {
            results.severity = 'Medium';
            results.type = 'Suspicious';
        } else {
            results.severity = 'Low';
            results.type = 'Likely Safe';
        }

        // Generate analysis summary
        results.analysis = `This URL has a risk score of ${results.riskScore}/100. ` +
            (results.indicators.length > 0 ? 
                `Issues found: ${results.indicators.join(', ')}` : 
                'No significant security issues detected.');

        return results;

    } catch (error) {
        throw new Error(`Invalid URL format: ${error.message}`);
    }
}

// Export routes
app.post('/export-text', authenticate, (req, res) => {
    try {
        const analysisData = JSON.parse(req.body.analysisData);
        if (!analysisData || !analysisData.url) {
            return res.status(400).json({
                success: false,
                message: 'No analysis data to export'
            });
        }

        const textContent = generateTextReport(analysisData);
        
        // Set headers for text file download
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename=security-analysis-${Date.now()}.txt`);
        res.send(textContent);
    } catch (error) {
        console.error('Text export error:', error);
        res.status(500).json({
            success: false,
            message: 'Error generating text report'
        });
    }
});

app.post('/export-pdf', authenticate, async (req, res) => {
    try {
        const analysisData = JSON.parse(req.body.analysisData);
        if (!analysisData || !analysisData.url) {
            return res.status(400).json({
                success: false,
                message: 'No analysis data to export'
            });
        }

        const pdfDoc = await generatePdfReport(analysisData);
        
        // Set headers for PDF file download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=security-analysis-${Date.now()}.pdf`);
        pdfDoc.pipe(res);
        pdfDoc.end();
    } catch (error) {
        console.error('PDF export error:', error);
        res.status(500).json({
            success: false,
            message: 'Error generating PDF report'
        });
    }
});

// Helper function to generate text report
function generateTextReport(data) {
    let report = `URL Security Analysis Report\n`;
    report += `=========================\n\n`;
    report += `Analysis Date: ${new Date().toLocaleString()}\n\n`;
    
    report += `Target URL: ${data.url}\n`;
    report += `Risk Score: ${data.riskScore}/100\n`;
    report += `Severity Level: ${data.severity}\n`;
    report += `Classification: ${data.type}\n\n`;

    report += `Analysis Summary:\n`;
    report += `----------------\n`;
    report += `${data.analysis}\n\n`;

    if (data.indicators && data.indicators.length > 0) {
    report += `Risk Indicators:\n`;
        report += `---------------\n`;
        data.indicators.forEach(indicator => {
            report += `• ${indicator}\n`;
        });
        report += '\n';
    }

    return report;
}

// Helper function to generate PDF report
function generatePdfReport(data) {
    const doc = new PDFDocument();
    
    // Title
    doc.fontSize(24)
       .text('URL Security Analysis Report', { align: 'center' })
       .moveDown(2);

    // Basic Information
    doc.fontSize(14)
       .text('Basic Information', { underline: true })
       .moveDown(1);

            doc.fontSize(12)
       .text(`Target URL: ${data.url}`)
       .text(`Risk Score: ${data.riskScore}/100`)
       .text(`Severity Level: ${data.severity}`)
       .text(`Classification: ${data.type}`)
       .moveDown(2);

    // Analysis Summary
    doc.fontSize(14)
       .text('Analysis Summary', { underline: true })
       .moveDown(1);

        doc.fontSize(12)
       .text(data.analysis)
       .moveDown(2);

    // Risk Indicators
    if (data.indicators && data.indicators.length > 0) {
        doc.fontSize(14)
           .text('Risk Indicators', { underline: true })
           .moveDown(1);

        data.indicators.forEach(indicator => {
        doc.fontSize(12)
               .text(`• ${indicator}`);
        });
        doc.moveDown(2);
    }

    // SSL/TLS Analysis
    if (data.ssl) {
        doc.fontSize(14)
           .text('SSL/TLS Analysis', { underline: true })
           .moveDown(1);

        if (data.ssl.secure) {
        doc.fontSize(12)
               .text(`Connection: Secure`)
               .text(`Issuer: ${data.ssl.issuer ? data.ssl.issuer.CN || 'Unknown' : 'Unknown'}`)
               .text(`Valid From: ${data.ssl.validFrom}`)
               .text(`Valid To: ${data.ssl.validTo}`)
               .text(`Protocol: ${data.ssl.protocol}`);
        } else {
            doc.fontSize(12)
               .text(`Connection: Not Secure`)
               .text(`Issue: ${data.ssl.error || 'Unknown error'}`);
        }
        doc.moveDown(2);
    }

    // Content Analysis
    if (data.contentAnalysis) {
        doc.fontSize(14)
           .text('Content Analysis', { underline: true })
           .moveDown(1);

        doc.fontSize(12)
           .text(`Redirect Count: ${data.contentAnalysis.redirects.count}`)
           .text(`Meta Refresh: ${data.contentAnalysis.redirects.hasMetaRefresh ? 'Yes' : 'No'}`)
           .text(`External Scripts: ${data.contentAnalysis.scripts.external}`);

        if (data.contentAnalysis.adAnalysis) {
            doc.moveDown(1)
               .text('Advertising Analysis:');
            Object.entries(data.contentAnalysis.adAnalysis).forEach(([key, value]) => {
                doc.text(`  • ${key}: ${value}`);
            });
        }
    }

    // Footer
    doc.moveDown(2)
       .fontSize(10)
       .text('Generated by URL Security Analyzer', { align: 'center' })
       .text(new Date().toLocaleString(), { align: 'center' });

    return doc;
}

// API Routes for Users
app.get('/users', async (req, res) => {
    try {
        const users = await User.find().select('-password'); // Exclude password field
        res.json({
            success: true,
            users: users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching users'
        });
    }
});

// API Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Create session
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions.set(sessionId, {
            userId: user._id,
            email: user.email
        });

        res.json({
            success: true,
            user: {
                id: user._id,
                email: user.email
            },
            sessionId: sessionId
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during login'
        });
    }
});

// API Register Route
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }

        // Check if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            });
        }

        // Create new user
        user = new User({ email, password });
        await user.save();

        // Create session
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions.set(sessionId, {
            userId: user._id,
            email: user.email
        });

        res.status(201).json({
            success: true,
            user: {
                id: user._id,
                email: user.email
            },
            sessionId: sessionId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during registration'
        });
    }
});

// Hash Analysis Routes
app.post('/api/analyze-hash', async (req, res) => {
    try {
        const { hash, hashType } = req.body;

        // Validate hash format based on type
        const hashPatterns = {
            'md5': /^[a-fA-F0-9]{32}$/,
            'sha1': /^[a-fA-F0-9]{40}$/,
            'sha256': /^[a-fA-F0-9]{64}$/,
            'sha512': /^[a-fA-F0-9]{128}$/
        };

        if (!hashType || !hashPatterns[hashType.toLowerCase()].test(hash)) {
            return res.status(400).json({ error: 'Invalid hash format' });
        }

        // Mock analysis results (replace with actual analysis logic)
        const analysisResult = {
            hashInfo: {
                hash: hash,
                type: hashType.toUpperCase()
            },
            analysisSummary: {
                status: 'Clean',
                confidence: 87,
                firstSeen: '2024-03-31'
            },
            detailedAnalysis: {
                reputation: [
                    { name: 'VirusTotal', status: 'malicious' },
                    { name: 'Hybrid Analysis', status: 'malicious' },
                    { name: 'AbuseIPDB', status: 'malicious' },
                    { name: 'AlienVault', status: 'clean' }
                ]
            },
            fileInfo: {
                type: 'Executable',
                size: '2.4 MB',
                magic: 'PE32+ executable for MS Windows',
                ssdeep: '3072:ha2k1H8+WsjOoHULUQ8KX4KCh12kH8+WsjOoHULUQ8KX4KC'
            },
            detectionHistory: [
                { date: '2024-03-15', scanner: 'Windows Defender', result: 'TrojanWin32/Emotet' },
                { date: '2024-03-15', scanner: 'Kaspersky', result: 'HEUR:Trojan.Win32.Generic' },
                { date: '2024-03-15', scanner: 'McAfee', result: 'Clean' }
            ]
        };

        // Store the result in session for the results page
        req.session.hashAnalysisResult = analysisResult;
        res.json({ success: true });

    } catch (error) {
        console.error('Hash analysis error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Hash Results Page Route
app.get('/hash-results', (req, res) => {
    const result = req.session.hashAnalysisResult;
    if (!result) {
        return res.redirect('/?error=No analysis results found');
        }

        res.render('hash-results', { 
        result: result,
        user: req.user || null,
            csrfToken: req.csrfToken()
        });
});

// Hash export routes
app.post('/export-hash-text', authenticate, (req, res) => {
    try {
        const result = req.body;
        if (!result || !result.hashInfo) {
            return res.status(400).json({
                error: 'No hash data to export'
            });
        }

        const textContent = generateHashReport(result);
        
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename=hash-analysis-${Date.now()}.txt`);
        res.send(textContent);
    } catch (error) {
        console.error('Hash text export error:', error);
        res.status(500).json({
            error: 'Error generating text report'
        });
    }
});

app.post('/export-hash-pdf', authenticate, (req, res) => {
    try {
        const result = req.body;
        if (!result || !result.hashInfo) {
            return res.status(400).json({
                error: 'No hash data to export'
            });
        }

        const doc = new PDFDocument();
        
        // Set response headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=hash-analysis-${Date.now()}.pdf`);
        
        // Pipe the PDF document to the response
        doc.pipe(res);
        
        // Add content to PDF
        doc.fontSize(24)
           .text('Hash Analysis Report', { align: 'center' })
           .moveDown(2);

        // Hash Information
        doc.fontSize(14)
           .text('Hash Information', { underline: true })
           .moveDown(1);

        doc.fontSize(12)
           .text(`Hash: ${result.hashInfo.hash}`)
           .text(`Type: ${result.hashInfo.type}`)
           .moveDown(2);

        // Analysis Summary
        doc.fontSize(14)
           .text('Analysis Summary', { underline: true })
           .moveDown(1);

        doc.fontSize(12)
           .text(`Status: ${result.analysisSummary.status}`)
           .text(`Confidence: ${result.analysisSummary.confidence}%`)
           .text(`First Seen: ${result.analysisSummary.firstSeen}`)
           .moveDown(2);

        // Reputation Information
        if (result.detailedAnalysis && result.detailedAnalysis.reputation) {
            doc.fontSize(14)
               .text('Reputation Information', { underline: true })
               .moveDown(1);

            result.detailedAnalysis.reputation.forEach(source => {
                doc.fontSize(12)
                   .text(`${source.name}: ${source.status}`);
            });
            doc.moveDown(2);
        }

        // Detection History
        if (result.detectionHistory) {
            doc.fontSize(14)
               .text('Detection History', { underline: true })
               .moveDown(1);

            result.detectionHistory.forEach(detection => {
                doc.fontSize(12)
                   .text(`${detection.date} - ${detection.scanner}: ${detection.result}`);
            });
        }

        // Footer
        doc.moveDown(2)
           .fontSize(10)
           .text('Generated by Hash Analyzer', { align: 'center' })
           .text(new Date().toLocaleString(), { align: 'center' });

        // Finalize PDF
        doc.end();
    } catch (error) {
        console.error('Hash PDF export error:', error);
        res.status(500).json({
            error: 'Error generating PDF report'
        });
    }
});

// Hash Analyzer Route
app.get('/hash-analyzer', (req, res) => {
    res.render('hash-analyzer', { user: req.user });
});

// Add JSON formatting middleware
app.use((req, res, next) => {
    const originalJson = res.json;
    res.json = function(obj) {
        if (obj && typeof obj === 'object') {
            return originalJson.call(this, JSON.stringify(obj, null, 2));
        }
        return originalJson.call(this, obj);
    };
    next();
});

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// File upload middleware configuration
app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max-file-size
    useTempFiles: true,
    tempFileDir: path.join(__dirname, 'temp'),
    debug: true,
    abortOnLimit: true,
    responseOnLimit: 'File size limit has been reached',
    safeFileNames: true,
    preserveExtension: true
}));

// File Scanner Route
app.post('/scan-file', async (req, res) => {
    console.log('Received file upload request');
    
    try {
        // Check if file exists in request
        if (!req.files || !req.files.file) {
            return res.status(400).json({
                success: false,
                error: 'No file uploaded'
            });
        }

        const file = req.files.file;
        
        // Log file information
        console.log('File details:', {
            name: file.name,
            size: file.size,
            mimetype: file.mimetype
        });

        // Validate file size
        const maxSize = 50 * 1024 * 1024; // 50MB
        if (file.size > maxSize) {
            return res.status(400).json({
                success: false,
                error: `File size (${(file.size / (1024 * 1024)).toFixed(2)}MB) exceeds limit of 50MB`
            });
        }

        // Validate file type
        const allowedTypes = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain',
            'application/json',
            'text/html',
            'image/jpeg',
            'image/png',
            'image/gif'
        ];

        if (!allowedTypes.includes(file.mimetype)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid file type. Supported types: PDF, DOC, DOCX, TXT, JSON, HTML, Images'
            });
        }

        // Generate unique filename
        const uniqueFilename = `${Date.now()}-${file.name}`;
        const filePath = path.join(uploadDir, uniqueFilename);

        try {
            // Move file to upload directory
            await file.mv(filePath);
            console.log('File saved successfully:', filePath);

            // Read file for analysis
            const fileBuffer = fs.readFileSync(filePath);
            const fileContent = fileBuffer.toString('utf8');

            // Calculate file hash
            const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

            // Initialize threat detection
            const threats = [];
            let riskScore = 0;

            // Define threat patterns
            const threatPatterns = {
                'Suspicious Script Tags': {
                    pattern: /<script\b[^>]*>[\s\S]*?<\/script>/gi,
                    score: 15
                },
                'Potential SQL Injection': {
                    pattern: /(\b(union|select|insert|update|delete|drop|alter)\b.*?(\b(from|into|table)\b))/gi,
                    score: 20
                },
                'Command Injection': {
                    pattern: /\b(exec|eval|system|shell_exec)\b/gi,
                    score: 25
                },
                'Base64 Content': {
                    pattern: /base64[^a-zA-Z0-9]/gi,
                    score: 10
                },
                'Suspicious URLs': {
                    pattern: /(https?:\/\/[^\s<>"']+)/gi,
                    score: 5
                },
                'Potential XSS': {
                    pattern: /<[^>]*?(javascript:|onload=|onerror=|onclick=)/gi,
                    score: 20
                }
            };

            // Analyze content for threats
            Object.entries(threatPatterns).forEach(([name, {pattern, score}]) => {
                const matches = (fileContent.match(pattern) || []).length;
                if (matches > 0) {
                    threats.push(`${name} (${matches} instance${matches > 1 ? 's' : ''})`);
                    riskScore += matches * score;
                }
            });

            // Check file extension
            const suspiciousExtensions = /\.(exe|dll|bat|cmd|msi|ps1|vbs|js)$/i;
            if (suspiciousExtensions.test(file.name)) {
                threats.push('Potentially dangerous file extension detected');
                riskScore += 50;
            }

            // Cap risk score at 100
            riskScore = Math.min(Math.round(riskScore), 100);

            // Prepare scan results
            const results = {
                name: file.name,
                size: file.size,
                sizeFormatted: formatFileSize(file.size),
                type: file.mimetype,
                hash: hash,
                riskScore: riskScore,
                riskLevel: riskScore <= 30 ? 'Low' : riskScore <= 70 ? 'Medium' : 'High',
                threats: threats,
                timestamp: new Date().toISOString(),
                scanDuration: '< 1 second'
            };

            // Clean up - delete the uploaded file
            fs.unlinkSync(filePath);
            console.log('Temporary file deleted:', filePath);

            // Send success response
            return res.json({
                success: true,
                results: results
            });

        } catch (error) {
            console.error('Error processing file:', error);
            // Clean up file if it exists
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
            return res.status(500).json({
                success: false,
                error: 'Error processing file: ' + error.message
            });
        }

    } catch (error) {
        console.error('File scan error:', error);
        return res.status(500).json({
            success: false,
            error: 'Error scanning file: ' + error.message
        });
    }
});

// Helper function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper function to generate hash text report
function generateHashReport(data) {
    let report = `Hash Analysis Report\n`;
    report += `===================\n\n`;
    report += `Analysis Date: ${new Date().toLocaleString()}\n\n`;
    
    report += `Hash Information:\n`;
    report += `-----------------\n`;
    report += `Hash: ${data.hashInfo.hash}\n`;
    report += `Type: ${data.hashInfo.type}\n\n`;

    report += `Analysis Summary:\n`;
    report += `-----------------\n`;
    report += `Status: ${data.analysisSummary.status}\n`;
    report += `Confidence: ${data.analysisSummary.confidence}%\n`;
    report += `First Seen: ${data.analysisSummary.firstSeen}\n\n`;

    if (data.detailedAnalysis && data.detailedAnalysis.reputation) {
        report += `Reputation Information:\n`;
        report += `---------------------\n`;
        data.detailedAnalysis.reputation.forEach(source => {
            report += `${source.name}: ${source.status}\n`;
        });
        report += '\n';
    }

    if (data.detectionHistory) {
        report += `Detection History:\n`;
        report += `-----------------\n`;
        data.detectionHistory.forEach(detection => {
            report += `${detection.date} - ${detection.scanner}: ${detection.result}\n`;
        });
    }

    return report;
} 