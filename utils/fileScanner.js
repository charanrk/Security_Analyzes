const crypto = require('crypto');
const FileType = require('file-type');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class FileScanner {
    constructor() {
        this.virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
        this.knownMalwareHashes = new Set([
            // Example known malware hashes (MD5)
            'e44e4978da6734b8f063a10e5d9b466a',
            '7b2f835752fca9d24496c18f0050c09c',
            // Add more known malware hashes
        ]);

        this.suspiciousPatterns = {
            executableContent: /\b(CreateProcess|WinExec|ShellExecute|system|exec|eval|Runtime\.getRuntime\(\)\.exec)\b/,
            networkActivity: /\b(Socket|HttpClient|URLConnection|WebClient|Dns|TcpClient)\b/,
            fileOperations: /\b(WriteFile|CreateFile|fopen|File\.Open|FileStream|mkdir|rmdir|unlink)\b/,
            registryAccess: /\b(RegCreateKey|RegSetValue|Registry|RegistryKey)\b/,
            processManipulation: /\b(OpenProcess|VirtualAlloc|WriteProcessMemory|CreateRemoteThread)\b/,
            obfuscation: /\b(base64_decode|chr|eval|fromCharCode|unescape)\b/,
            persistence: /\b(CurrentVersion\\Run|HKEY_LOCAL_MACHINE\\SOFTWARE|StartupItems|LaunchAgents)\b/,
            antiAnalysis: /\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|GetTickCount|QueryPerformanceCounter)\b/
        };

        this.suspiciousFileTypes = new Set([
            'application/x-msdownload',
            'application/x-executable',
            'application/x-dosexec',
            'application/x-msi',
            'application/vnd.microsoft.portable-executable'
        ]);

        this.supportedMimeTypes = [
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
        
        this.maxFileSizeBytes = 50 * 1024 * 1024; // 50MB

        this.executableExtensions = ['.exe', '.dll', '.bat', '.cmd', '.msi', '.ps1', '.vbs', '.js'];
    }

    async scanFile(filePath) {
        try {
            // Get basic file info
            const stats = await fs.promises.stat(filePath);
            const fileInfo = {
                name: path.basename(filePath),
                size: stats.size,
                sizeFormatted: this.formatFileSize(stats.size),
                created: stats.birthtime,
                modified: stats.mtime,
                extension: path.extname(filePath).toLowerCase()
            };

            // Read file buffer for type detection
            const buffer = await fs.promises.readFile(filePath);
            
            // Detect file type
            const typeInfo = await FileType.fromBuffer(buffer);
            const mimeType = typeInfo ? typeInfo.mime : this._getMimeTypeFromExtension(filePath);

            // Calculate hashes
            const hashes = await this.calculateHashes(filePath);

            // Perform security assessment
            const security = this.assessSecurity(filePath, mimeType);

            return {
                status: 'success',
                timestamp: new Date().toISOString(),
                fileInfo,
                type: {
                    mime: mimeType,
                    detected: typeInfo ? typeInfo.ext : null
                },
                hashes,
                security,
                processingTime: process.hrtime()[0]
            };
        } catch (error) {
            console.error('File scanning error:', error);
            throw new Error(`File scanning failed: ${error.message}`);
        }
    }

    _getMimeTypeFromExtension(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes = {
            '.txt': 'text/plain',
            '.html': 'text/html',
            '.json': 'application/json',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        };
        return mimeTypes[ext] || 'application/octet-stream';
    }

    formatFileSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = bytes;
        let unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }

    assessSecurity(filePath, mimeType) {
        const ext = path.extname(filePath).toLowerCase();
        const isExecutable = this.executableExtensions.includes(ext);
        const isBinary = !mimeType.startsWith('text/') && !mimeType.includes('json');

        return {
            isExecutable,
            isBinary,
            riskLevel: isExecutable ? 'high' : (isBinary ? 'medium' : 'low'),
            warnings: [
                ...(isExecutable ? ['File is executable and may contain malicious code'] : []),
                ...(isBinary ? ['File contains binary data'] : []),
                ...(ext === '.js' ? ['JavaScript file may contain executable code'] : [])
            ]
        };
    }

    calculateHashes(filePath) {
        return new Promise((resolve, reject) => {
            const md5Hash = crypto.createHash('md5');
            const sha1Hash = crypto.createHash('sha1');
            const sha256Hash = crypto.createHash('sha256');

            const stream = fs.createReadStream(filePath);

            stream.on('data', (data) => {
                md5Hash.update(data);
                sha1Hash.update(data);
                sha256Hash.update(data);
            });

            stream.on('end', () => {
                resolve({
                    md5: md5Hash.digest('hex'),
                    sha1: sha1Hash.digest('hex'),
                    sha256: sha256Hash.digest('hex')
                });
            });

            stream.on('error', reject);
        });
    }

    async analyzeFileContent(buffer, fileType) {
        const results = {
            isSuspiciousFileType: false,
            suspiciousPatterns: [],
            binaryAnalysis: {},
            stringAnalysis: {},
            isEncrypted: false,
            entropy: this.calculateEntropy(buffer)
        };

        // Check file type
        if (fileType && this.suspiciousFileTypes.has(fileType.mime)) {
            results.isSuspiciousFileType = true;
        }

        // Convert buffer to string for pattern matching
        const fileContent = buffer.toString('utf8');

        // Check for suspicious patterns
        for (const [patternName, pattern] of Object.entries(this.suspiciousPatterns)) {
            if (pattern.test(fileContent)) {
                results.suspiciousPatterns.push(patternName);
            }
        }

        // Analyze strings in binary files
        if (this.isBinaryFile(buffer)) {
            results.binaryAnalysis = await this.analyzeBinaryFile(buffer);
            results.stringAnalysis = this.extractStrings(buffer);
        }

        // Check for encryption indicators
        results.isEncrypted = this.checkForEncryption(buffer);

        return results;
    }

    async analyzeBinaryFile(buffer) {
        const results = {
            hasExecutableCode: false,
            suspiciousImports: [],
            resourceAnalysis: {}
        };

        // Check for PE file format
        if (buffer.slice(0, 2).toString('hex') === '4d5a') { // MZ header
            results.hasExecutableCode = true;
            
            // Analyze imports (simplified)
            const imports = this.extractImports(buffer);
            results.suspiciousImports = imports.filter(imp => 
                imp.toLowerCase().includes('inject') ||
                imp.toLowerCase().includes('remote') ||
                imp.toLowerCase().includes('crypt')
            );
        }

        return results;
    }

    calculateEntropy(buffer) {
        const bytes = new Uint8Array(buffer);
        const frequency = new Array(256).fill(0);
        
        bytes.forEach(byte => frequency[byte]++);
        
        return frequency.reduce((entropy, count) => {
            if (count === 0) return entropy;
            const probability = count / buffer.length;
            return entropy - probability * Math.log2(probability);
        }, 0);
    }

    extractStrings(buffer) {
        const minLength = 4;
        const strings = [];
        let currentString = '';
        
        for (let i = 0; i < buffer.length; i++) {
            const char = String.fromCharCode(buffer[i]);
            if (/[\x20-\x7E]/.test(char)) {
                currentString += char;
            } else if (currentString.length >= minLength) {
                strings.push(currentString);
                currentString = '';
            } else {
                currentString = '';
            }
        }
        
        return {
            total: strings.length,
            suspicious: strings.filter(str => 
                this.isSuspiciousString(str)
            )
        };
    }

    isSuspiciousString(str) {
        const suspiciousKeywords = [
            'cmd.exe', 'powershell', 'wget', 'curl',
            'http://', 'https://', 'ftp://',
            'admin', 'password', 'login',
            'hack', 'crack', 'keygen',
            'registry', 'decrypt', 'encrypt'
        ];
        
        return suspiciousKeywords.some(keyword => 
            str.toLowerCase().includes(keyword)
        );
    }

    async analyzeMetadata(filePath, buffer, fileType) {
        const stats = await fs.stat(filePath);
        
        const metadata = {
            size: stats.size,
            created: stats.birthtime,
            modified: stats.mtime,
            accessed: stats.atime,
            permissions: stats.mode,
            mimeType: fileType ? fileType.mime : 'unknown',
            extension: path.extname(filePath),
            isHidden: path.basename(filePath).startsWith('.'),
            signatures: await this.checkFileSignatures(buffer)
        };

        // Additional metadata for specific file types
        if (fileType) {
            switch (fileType.mime) {
                case 'application/x-msdownload':
                case 'application/x-executable':
                    metadata.executable = await this.analyzeExecutable(filePath);
                    break;
                case 'application/pdf':
                    metadata.pdf = await this.analyzePDF(buffer);
                    break;
                // Add more file type specific analysis
            }
        }

        return metadata;
    }

    async checkFileSignatures(buffer) {
        const signatures = {
            hasCertificate: false,
            isSignatureValid: false,
            certificateDetails: null
        };

        // Check for digital signatures in PE files
        if (buffer.slice(0, 2).toString('hex') === '4d5a') {
            try {
                const sigcheckOutput = await execPromise('sigcheck -nobanner ' + filePath);
                signatures.hasCertificate = !sigcheckOutput.includes('Unsigned');
                signatures.isSignatureValid = sigcheckOutput.includes('Valid signature');
                // Parse certificate details if available
                if (signatures.hasCertificate) {
                    signatures.certificateDetails = this.parseCertificateInfo(sigcheckOutput);
                }
            } catch (error) {
                console.error('Signature check error:', error);
            }
        }

        return signatures;
    }

    async checkVirusTotal(hash) {
        try {
            const response = await axios.get(
                `https://www.virustotal.com/vtapi/v2/file/report?apikey=${this.virusTotalApiKey}&resource=${hash}`
            );

            return {
                found: response.data.response_code === 1,
                positives: response.data.positives || 0,
                total: response.data.total || 0,
                scanDate: response.data.scan_date,
                scans: response.data.scans || {}
            };
        } catch (error) {
            console.error('VirusTotal API error:', error);
            return null;
        }
    }

    calculateRiskScore({ fileType, contentAnalysis, metadata, virusTotalResults }) {
        let score = 0;
        const riskFactors = [];

        // File type risk
        if (contentAnalysis.isSuspiciousFileType) {
            score += 20;
            riskFactors.push('Suspicious file type');
        }

        // Suspicious patterns
        score += contentAnalysis.suspiciousPatterns.length * 10;
        if (contentAnalysis.suspiciousPatterns.length > 0) {
            riskFactors.push(`Contains suspicious patterns: ${contentAnalysis.suspiciousPatterns.join(', ')}`);
        }

        // Binary analysis
        if (contentAnalysis.binaryAnalysis.hasExecutableCode) {
            score += 15;
            riskFactors.push('Contains executable code');
        }

        // Entropy check
        if (contentAnalysis.entropy > 7.5) {
            score += 15;
            riskFactors.push('High entropy (possible encryption/packing)');
        }

        // Suspicious strings
        if (contentAnalysis.stringAnalysis.suspicious?.length > 0) {
            score += Math.min(contentAnalysis.stringAnalysis.suspicious.length * 5, 20);
            riskFactors.push('Contains suspicious strings');
        }

        // VirusTotal results
        if (virusTotalResults && virusTotalResults.positives > 0) {
            score += Math.min(virusTotalResults.positives * 5, 30);
            riskFactors.push(`Detected by ${virusTotalResults.positives} antivirus engines`);
        }

        // Metadata analysis
        if (metadata.isHidden) {
            score += 5;
            riskFactors.push('Hidden file');
        }

        if (!metadata.signatures.isSignatureValid && metadata.mimeType === 'application/x-msdownload') {
            score += 15;
            riskFactors.push('Unsigned executable');
        }

        // Cap the score at 100
        score = Math.min(score, 100);

        // Determine risk level
        let riskLevel;
        if (score >= 75) {
            riskLevel = 'Critical';
        } else if (score >= 50) {
            riskLevel = 'High';
        } else if (score >= 25) {
            riskLevel = 'Medium';
        } else {
            riskLevel = 'Low';
        }

        return {
            score,
            level: riskLevel,
            factors: riskFactors
        };
    }

    isBinaryFile(buffer) {
        // Check first 1000 bytes for null bytes
        const sample = buffer.slice(0, 1000);
        return sample.includes(0x00);
    }

    checkForEncryption(buffer) {
        // High entropy is often an indicator of encryption
        return this.calculateEntropy(buffer) > 7.5;
    }

    extractImports(buffer) {
        // Simplified PE import extraction
        const imports = [];
        const str = buffer.toString('utf8');
        const dllPattern = /\w+\.(dll|exe|sys)/gi;
        const matches = str.match(dllPattern) || [];
        return [...new Set(matches)];
    }

    async analyzeExecutable(filePath) {
        try {
            const { stdout } = await execPromise(`file "${filePath}"`);
            return {
                type: stdout.includes('PE32+') ? '64-bit' : '32-bit',
                isDLL: stdout.includes('DLL'),
                compiler: this.detectCompiler(stdout)
            };
        } catch (error) {
            console.error('Executable analysis error:', error);
            return null;
        }
    }

    async analyzePDF(buffer) {
        const analysis = {
            version: null,
            hasJavaScript: false,
            hasEmbeddedFiles: false,
            hasAcroform: false,
            hasXFA: false
        };

        const content = buffer.toString('utf8');
        analysis.version = content.match(/^%PDF-(\d+\.\d+)/)?.[1];
        analysis.hasJavaScript = /\/JavaScript/.test(content);
        analysis.hasEmbeddedFiles = /\/EmbeddedFiles/.test(content);
        analysis.hasAcroform = /\/AcroForm/.test(content);
        analysis.hasXFA = /\/XFA/.test(content);

        return analysis;
    }

    detectCompiler(fileOutput) {
        if (fileOutput.includes('Microsoft Visual C++')) return 'MSVC';
        if (fileOutput.includes('Delphi')) return 'Delphi';
        if (fileOutput.includes('MinGW')) return 'MinGW';
        return 'Unknown';
    }

    parseCertificateInfo(sigcheckOutput) {
        const certInfo = {};
        const lines = sigcheckOutput.split('\n');
        
        for (const line of lines) {
            if (line.includes('Publisher:')) {
                certInfo.publisher = line.split(':')[1].trim();
            }
            if (line.includes('Signing date:')) {
                certInfo.signingDate = line.split(':')[1].trim();
            }
        }
        
        return certInfo;
    }
}

module.exports = FileScanner; 