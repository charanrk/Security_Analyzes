const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

async function setup() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/url-analyzer', {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Connected to MongoDB');

        // Create test user
        const testUser = new User({
            email: 'test@example.com',
            password: 'password123'
        });

        await testUser.save();
        console.log('Test user created successfully');
        console.log('Email: test@example.com');
        console.log('Password: password123');

        console.log('\nSetup completed successfully!');
    } catch (error) {
        console.error('Setup failed:', error.message);
        if (error.message.includes('ECONNREFUSED')) {
            console.log('\nTroubleshooting steps:');
            console.log('1. Make sure MongoDB is installed');
            console.log('2. Open PowerShell as Administrator');
            console.log('3. Run: net start MongoDB');
            console.log('4. Try running this setup script again');
        }
    } finally {
        await mongoose.connection.close();
    }
}

setup(); 