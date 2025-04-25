const crypto = require('crypto');
const axios = require('axios');

const HASH_PATTERNS = {
    MD5: /^[a-f0-9]{32}$/i,
    SHA1: /^[a-f0-9]{40}$/i,
    SHA256: /^[a-f0-9]{64}$/i,
    SHA512: /^[a-f0-9]{128}$/i
};

async function analyzeHash(hash) {
    const type = detectHashType(hash);
    const length = hash.length;
    const firstSeen = new Date().toISOString().split('T')[0];
    
    // Reputation check from multiple sources
    const reputationInfo = await checkReputation(hash);
    
    // File analysis if available
    const fileInfo = await getFileInformation(hash);
    
    // Detection history
    const detectionHistory = await getDetectionHistory(hash);

    return {
        hashInfo: {
            hash,
            type,
            length: `${length} characters`
        },
        analysisSummary: {
            status: reputationInfo.status,
            confidence: reputationInfo.confidence,
            firstSeen
        },
        detailedAnalysis: {
            reputation: reputationInfo.sources,
            fileInfo,
            detectionHistory
        }
    };
}

function detectHashType(hash) {
    for (const [type, pattern] of Object.entries(HASH_PATTERNS)) {
        if (pattern.test(hash)) {
            return type;
        }
    }
    return 'Unknown';
}

async function checkReputation(hash) {
    // Simulated reputation check from multiple sources
    const sources = {
        VirusTotal: { status: 'malicious', confidence: 74 },
        HybridAnalysis: { status: 'malicious', confidence: 68 },
        AbuseIPDB: { status: 'malicious', confidence: 82 },
        AlienVault: { status: 'malicious', confidence: 76 }
    };

    // Calculate overall confidence
    const avgConfidence = Math.round(
        Object.values(sources).reduce((acc, curr) => acc + curr.confidence, 0) / Object.keys(sources).length
    );

    return {
        status: 'Malicious',
        confidence: avgConfidence,
        sources: Object.entries(sources).map(([name, data]) => ({
            name,
            status: data.status
        }))
    };
}

async function getFileInformation(hash) {
    // Simulated file information
    return {
        fileType: 'Executable',
        size: '2.4 MB',
        magic: 'PE32+ executable for MS Windows',
        ssDeep: '3072:hsk2kHt8+Wojp0oHULUQ8KX4KC:h12kHt8+Wojp0'
    };
}

async function getDetectionHistory(hash) {
    // Simulated detection history
    return [
        {
            date: '2024-03-15',
            scanner: 'Windows Defender',
            result: 'Trojan:Win32/Emotet'
        },
        {
            date: '2024-03-15',
            scanner: 'Kaspersky',
            result: 'HEUR:Trojan.Win32.Generic'
        },
        {
            date: '2024-03-15',
            scanner: 'McAfee',
            result: 'Clean'
        }
    ];
}

function generateHash(text, algorithm) {
    const validAlgorithms = ['md5', 'sha1', 'sha256', 'sha512'];
    if (!validAlgorithms.includes(algorithm.toLowerCase())) {
        throw new Error('Invalid hash algorithm');
    }
    return crypto
        .createHash(algorithm.toLowerCase())
        .update(text)
        .digest('hex');
}

module.exports = {
    analyzeHash,
    detectHashType,
    generateHash
}; 