const axios = require('axios');
const whois = require('whois-json');
const { Certificate } = require('@fidm/x509');
const tls = require('tls');
const levenshtein = require('fast-levenshtein');
const { parse } = require('url');
const dns = require('dns').promises;

class PhishingDetector {
    constructor() {
        this.googleSafeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
        this.virusTotalKey = process.env.VIRUSTOTAL_API_KEY;
        this.commonBrands = [
            'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix',
            'paypal', 'bank', 'wells', 'chase', 'citi', 'amex', 'dropbox',
            'linkedin', 'twitter', 'instagram', 'whatsapp'
        ];
    }

    async checkPhishingDatabases(url) {
        const results = {
            googleSafeBrowsing: null,
            virusTotal: null
        };

        try {
            // Google Safe Browsing API check
            if (this.googleSafeBrowsingKey) {
                const safeBrowsingResponse = await axios.post(
                    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.googleSafeBrowsingKey}`,
                    {
                        client: {
                            clientId: "phishing-detector",
                            clientVersion: "1.0.0"
                        },
                        threatInfo: {
                            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            platformTypes: ["ANY_PLATFORM"],
                            threatEntryTypes: ["URL"],
                            threatEntries: [{ url }]
                        }
                    }
                );
                results.googleSafeBrowsing = {
                    isClean: !safeBrowsingResponse.data.matches,
                    threats: safeBrowsingResponse.data.matches || []
                };
            }

            // VirusTotal API check
            if (this.virusTotalKey) {
                const vtResponse = await axios.get(
                    `https://www.virustotal.com/vtapi/v2/url/report?apikey=${this.virusTotalKey}&resource=${encodeURIComponent(url)}`
                );
                results.virusTotal = {
                    isClean: vtResponse.data.positives === 0,
                    positives: vtResponse.data.positives,
                    total: vtResponse.data.total
                };
            }
        } catch (error) {
            console.error('Error checking phishing databases:', error);
        }

        return results;
    }

    async checkDomainAge(domain) {
        try {
            const whoisData = await whois(domain);
            const creationDate = new Date(whoisData.creationDate);
            const ageInDays = (new Date() - creationDate) / (1000 * 60 * 60 * 24);
            
            return {
                creationDate,
                ageInDays,
                registrar: whoisData.registrar,
                isNew: ageInDays < 30 // Flag domains less than 30 days old
            };
        } catch (error) {
            console.error('Error checking domain age:', error);
            return null;
        }
    }

    async checkLookAlikeDomain(domain) {
        const results = {
            similarBrands: [],
            confusableDomains: [],
            isSuspicious: false
        };

        // Check for brand similarity
        for (const brand of this.commonBrands) {
            const distance = levenshtein.get(domain.toLowerCase(), brand);
            if (distance <= 3 && domain.toLowerCase() !== brand) {
                results.similarBrands.push({
                    brand,
                    distance
                });
                results.isSuspicious = true;
            }
        }

        // Check for homograph attacks (similar-looking characters)
        const homographMap = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
            'ѕ': 's', 'і': 'i', 'l': '1', 'O': '0'
        };

        let normalizedDomain = domain;
        for (const [cyrillic, latin] of Object.entries(homographMap)) {
            if (domain.includes(cyrillic)) {
                normalizedDomain = normalizedDomain.replace(new RegExp(cyrillic, 'g'), latin);
                results.isSuspicious = true;
            }
        }

        if (normalizedDomain !== domain) {
            results.confusableDomains.push(normalizedDomain);
        }

        return results;
    }

    async checkSSLCertificate(domain) {
        return new Promise((resolve) => {
            try {
                const socket = tls.connect({
                    host: domain,
                    port: 443,
                    timeout: 5000,
                    rejectUnauthorized: false
                }, () => {
                    const cert = socket.getPeerCertificate(true);
                    socket.end();

                    if (!cert) {
                        resolve({
                            hasSSL: false,
                            isValid: false,
                            details: null
                        });
                        return;
                    }

                    const now = Date.now();
                    const certInfo = {
                        subject: cert.subject,
                        issuer: cert.issuer,
                        validFrom: new Date(cert.valid_from),
                        validTo: new Date(cert.valid_to),
                        isValid: now > new Date(cert.valid_from) && now < new Date(cert.valid_to),
                        isSelfSigned: cert.issuer.CN === cert.subject.CN,
                        isWildcard: cert.subject.CN && cert.subject.CN.startsWith('*.')
                    };

                    resolve({
                        hasSSL: true,
                        isValid: certInfo.isValid && !certInfo.isSelfSigned,
                        details: certInfo
                    });
                });

                socket.on('error', (error) => {
                    console.error('SSL certificate check error:', error);
                    resolve({
                        hasSSL: false,
                        isValid: false,
                        error: error.message
                    });
                });
            } catch (error) {
                console.error('SSL certificate check error:', error);
                resolve({
                    hasSSL: false,
                    isValid: false,
                    error: error.message
                });
            }
        });
    }

    checkSuspiciousPatterns(url) {
        const parsedUrl = parse(url);
        const patterns = {
            suspiciousKeywords: /(secure|login|signin|verify|account|update|confirm|banking|password|credential)/i,
            excessiveSubdomains: /(?:[^./]+\.){4,}[^./]+$/,
            numericDomain: /^[\d.-]+$/,
            dashesInDomain: /-{2,}/,
            mixedCharacterSets: /[А-Яа-я].+[A-Za-z]|[A-Za-z].+[А-Яа-я]/,
            uncommonTLD: /\.(xyz|top|win|loan|online|stream|gdn|racing|date|download|tokyo)$/i,
            ipAddressUrl: /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        };

        const results = {
            suspiciousPatterns: [],
            riskLevel: 'low'
        };

        let riskScore = 0;

        // Check domain for suspicious patterns
        if (patterns.suspiciousKeywords.test(parsedUrl.hostname)) {
            results.suspiciousPatterns.push('Contains suspicious keywords');
            riskScore += 2;
        }

        if (patterns.excessiveSubdomains.test(parsedUrl.hostname)) {
            results.suspiciousPatterns.push('Excessive number of subdomains');
            riskScore += 3;
        }

        if (patterns.numericDomain.test(parsedUrl.hostname)) {
            results.suspiciousPatterns.push('Fully numeric domain');
            riskScore += 2;
        }

        if (patterns.dashesInDomain.test(parsedUrl.hostname)) {
            results.suspiciousPatterns.push('Multiple consecutive dashes');
            riskScore += 1;
        }

        if (patterns.mixedCharacterSets.test(parsedUrl.hostname)) {
            results.suspiciousPatterns.push('Mixed character sets (potential homograph attack)');
            riskScore += 4;
        }

        if (patterns.uncommonTLD.test(parsedUrl.hostname)) {
            results.suspiciousPatterns.push('Uncommon TLD');
            riskScore += 1;
        }

        if (patterns.ipAddressUrl.test(url)) {
            results.suspiciousPatterns.push('IP address instead of domain name');
            riskScore += 3;
        }

        // Set risk level based on score
        if (riskScore >= 6) {
            results.riskLevel = 'high';
        } else if (riskScore >= 3) {
            results.riskLevel = 'medium';
        }

        results.riskScore = riskScore;
        return results;
    }

    async analyzeUrl(url) {
        const parsedUrl = parse(url);
        const domain = parsedUrl.hostname;

        const [
            phishingDbResults,
            domainAge,
            lookAlikeResults,
            sslResults,
            patternResults
        ] = await Promise.all([
            this.checkPhishingDatabases(url),
            this.checkDomainAge(domain),
            this.checkLookAlikeDomain(domain),
            this.checkSSLCertificate(domain),
            this.checkSuspiciousPatterns(url)
        ]);

        return {
            url,
            domain,
            timestamp: new Date().toISOString(),
            phishingDatabases: phishingDbResults,
            domainAge,
            lookAlikeDomain: lookAlikeResults,
            sslCertificate: sslResults,
            suspiciousPatterns: patternResults,
            overallRisk: this.calculateOverallRisk({
                phishingDbResults,
                domainAge,
                lookAlikeResults,
                sslResults,
                patternResults
            })
        };
    }

    calculateOverallRisk(results) {
        let riskScore = 0;
        let riskFactors = [];

        // Check phishing databases
        if (results.phishingDbResults.googleSafeBrowsing && !results.phishingDbResults.googleSafeBrowsing.isClean) {
            riskScore += 5;
            riskFactors.push('Found in Google Safe Browsing database');
        }
        if (results.phishingDbResults.virusTotal && !results.phishingDbResults.virusTotal.isClean) {
            riskScore += 5;
            riskFactors.push('Flagged by VirusTotal');
        }

        // Check domain age
        if (results.domainAge && results.domainAge.isNew) {
            riskScore += 3;
            riskFactors.push('Domain is less than 30 days old');
        }

        // Check look-alike domain
        if (results.lookAlikeDomain.isSuspicious) {
            riskScore += 4;
            riskFactors.push('Similar to known brand or contains confusable characters');
        }

        // Check SSL certificate
        if (!results.sslResults.hasSSL || !results.sslResults.isValid) {
            riskScore += 3;
            riskFactors.push('Invalid or missing SSL certificate');
        }

        // Add pattern recognition score
        riskScore += results.patternResults.riskScore;
        riskFactors = [...riskFactors, ...results.patternResults.suspiciousPatterns];

        let riskLevel;
        if (riskScore >= 10) {
            riskLevel = 'high';
        } else if (riskScore >= 5) {
            riskLevel = 'medium';
        } else {
            riskLevel = 'low';
        }

        return {
            score: riskScore,
            level: riskLevel,
            factors: riskFactors
        };
    }
}

module.exports = PhishingDetector; 