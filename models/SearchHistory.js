const mongoose = require('mongoose');

const searchHistorySchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true
    },
    url: {
        type: String,
        required: function() {
            return this.type === 'url';
        }
    },
    hash: {
        type: String,
        required: function() {
            return this.type === 'hash';
        }
    },
    type: {
        type: String,
        enum: ['url', 'hash'],
        required: true
    },
    severity: {
        type: String,
        required: true
    },
    analysis: String,
    timestamp: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('SearchHistory', searchHistorySchema); 