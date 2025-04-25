const request = require('supertest');
const app = require('../app');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

describe('Authentication System Tests', () => {
    beforeAll(async () => {
        // Connect to test database only if not already connected
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(process.env.MONGODB_URI_TEST || 'mongodb://localhost:27017/url-analyzer-test');
        }
    });

    beforeEach(async () => {
        // Clear users collection before each test
        if (mongoose.connection.readyState === 1) {
            await User.deleteMany({});
        }
    });

    afterAll(async () => {
        // Disconnect after all tests only if connected
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.close();
        }
    });

    describe('User Registration', () => {
        const validUser = {
            email: 'test@example.com',
            password: 'Test123!@#',
            terms: true
        };

        test('Should register with valid credentials', async () => {
            const res = await request(app)
                .post('/register')
                .send(validUser);
            
            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('token');

            // Check if user was created in database
            const user = await User.findOne({ email: validUser.email });
            expect(user).toBeTruthy();
            expect(user.email).toBe(validUser.email);
        });

        test('Should hash password before saving', async () => {
            await request(app)
                .post('/register')
                .send(validUser);

            const user = await User.findOne({ email: validUser.email });
            expect(user.password).not.toBe(validUser.password);
            expect(await bcrypt.compare(validUser.password, user.password)).toBe(true);
        });

        test('Should reject weak passwords', async () => {
            const weakPasswords = [
                'short',             // Too short
                'nocapital123!',     // No uppercase
                'NOLOWER123!',       // No lowercase
                'NoSpecial123',      // No special chars
                'NoNumber!!',        // No numbers
                'aaa111!!!',         // Not enough unique chars
            ];

            for (const password of weakPasswords) {
                const res = await request(app)
                    .post('/register')
                    .send({ ...validUser, password });
                
                expect(res.status).toBe(400);
                expect(res.body).toHaveProperty('errors');
            }
        });

        test('Should reject duplicate emails', async () => {
            // Register first user
            await request(app)
                .post('/register')
                .send(validUser);

            // Try to register same email again
            const res = await request(app)
                .post('/register')
                .send(validUser);

            expect(res.status).toBe(400);
            expect(res.body.message).toContain('exists');
        });
    });

    describe('User Login', () => {
        const testUser = {
            email: 'test@example.com',
            password: 'Test123!@#'
        };

        beforeEach(async () => {
            // Create a test user before each login test
            await request(app)
                .post('/register')
                .send({ ...testUser, terms: true });
        });

        test('Should login with correct credentials', async () => {
            const res = await request(app)
                .post('/login')
                .send(testUser);

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('token');
        });

        test('Should reject invalid password', async () => {
            const res = await request(app)
                .post('/login')
                .send({
                    email: testUser.email,
                    password: 'wrongpassword'
                });

            expect(res.status).toBe(401);
            expect(res.body.message).toContain('Invalid credentials');
        });

        test('Should reject non-existent email', async () => {
            const res = await request(app)
                .post('/login')
                .send({
                    email: 'nonexistent@example.com',
                    password: testUser.password
                });

            expect(res.status).toBe(401);
            expect(res.body.message).toContain('Invalid credentials');
        });
    });

    describe('Password Reset', () => {
        const testUser = {
            email: 'test@example.com',
            password: 'Test123!@#'
        };

        beforeEach(async () => {
            await request(app)
                .post('/register')
                .send({ ...testUser, terms: true });
        });

        test('Should generate reset token', async () => {
            const res = await request(app)
                .post('/forgot-password')
                .send({ email: testUser.email });

            expect(res.status).toBe(200);
            
            const user = await User.findOne({ email: testUser.email });
            expect(user.resetPasswordToken).toBeTruthy();
            expect(user.resetPasswordExpires).toBeInstanceOf(Date);
        });

        test('Should reset password with valid token', async () => {
            // Request password reset
            await request(app)
                .post('/forgot-password')
                .send({ email: testUser.email });

            const user = await User.findOne({ email: testUser.email });
            const token = user.resetPasswordToken;

            // Reset password
            const newPassword = 'NewTest456!@#';
            const res = await request(app)
                .post(`/reset-password/${token}`)
                .send({ password: newPassword });

            expect(res.status).toBe(200);

            // Try logging in with new password
            const loginRes = await request(app)
                .post('/login')
                .send({
                    email: testUser.email,
                    password: newPassword
                });

            expect(loginRes.status).toBe(200);
        });

        test('Should reject expired reset tokens', async () => {
            // Request password reset
            await request(app)
                .post('/forgot-password')
                .send({ email: testUser.email });

            // Expire the token
            await User.findOneAndUpdate(
                { email: testUser.email },
                { resetPasswordExpires: new Date(Date.now() - 3600000) }
            );

            const user = await User.findOne({ email: testUser.email });
            const token = user.resetPasswordToken;

            // Try to reset password with expired token
            const res = await request(app)
                .post(`/reset-password/${token}`)
                .send({ password: 'NewTest456!@#' });

            expect(res.status).toBe(400);
            expect(res.body.message).toContain('expired');
        });
    });

    describe('Password Security', () => {
        test('Should properly hash passwords with bcrypt', async () => {
            const password = 'Test123!@#';
            const user = new User({
                email: 'test@example.com',
                password
            });

            await user.save();

            // Verify password is hashed
            expect(user.password).not.toBe(password);
            expect(user.password).toMatch(/^\$2[aby]\$\d{1,2}\$/); // bcrypt hash pattern
            
            // Verify password can be compared
            const isMatch = await user.comparePassword(password);
            expect(isMatch).toBe(true);
        });

        test('Should use different salts for same password', async () => {
            const password = 'Test123!@#';
            
            // Create two users with same password
            const user1 = await User.create({
                email: 'test1@example.com',
                password
            });

            const user2 = await User.create({
                email: 'test2@example.com',
                password
            });

            // Verify hashes are different
            expect(user1.password).not.toBe(user2.password);
        });
    });
}); 