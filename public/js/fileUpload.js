// File upload handling code
document.addEventListener('DOMContentLoaded', function() {
    // Get all required elements
    const fileForm = document.getElementById('file-scan-form');
    const fileInput = document.getElementById('file-input');
    const dropZone = document.getElementById('drop-zone');
    const filePreview = document.getElementById('file-preview');
    const errorDisplay = document.getElementById('error-display');
    const uploadStatus = document.getElementById('upload-status');
    const scanButton = document.getElementById('scan-button');

    // Initially disable the scan button
    if (scanButton) {
        scanButton.disabled = true;
    }

    const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    const ALLOWED_TYPES = [
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

    // Handle form submission
    if (fileForm) {
        fileForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!fileInput || !fileInput.files || !fileInput.files[0]) {
                showError('Please select a file first');
                return;
            }

            const file = fileInput.files[0];
            
            try {
                // Clear previous errors and show upload status
                clearError();
                showUploadStatus('Scanning file...');
                if (scanButton) scanButton.disabled = true;

                const formData = new FormData();
                formData.append('file', file);

                // Get CSRF token from meta tag
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                
                const response = await fetch('/scan-file', {
                    method: 'POST',
                    headers: csrfToken ? {
                        'CSRF-Token': csrfToken
                    } : {},
                    body: formData
                });

                const data = await response.json();
                console.log('Server response:', data); // Debug log

                if (!response.ok) {
                    throw new Error(data.error || 'Error scanning file');
                }

                // Display scan results
                displayScanResults(data.results);
                hideUploadStatus();

            } catch (error) {
                console.error('File scan error:', error);
                hideUploadStatus();
                showError(error.message || 'Error scanning file. Please try again.');
            } finally {
                if (scanButton) scanButton.disabled = false;
            }
        });
    }

    // Handle file selection
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelection);
    }

    // Handle drag and drop
    if (dropZone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, unhighlight, false);
        });

        dropZone.addEventListener('drop', handleDrop, false);
    }

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        dropZone.classList.add('border-blue-500', 'bg-gray-800');
    }

    function unhighlight(e) {
        dropZone.classList.remove('border-blue-500', 'bg-gray-800');
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelection();
        }
    }

    function handleFileSelection() {
        clearError();
        hideUploadStatus();
        
        if (!fileInput || !fileInput.files || !fileInput.files[0]) {
            if (scanButton) scanButton.disabled = true;
            clearFilePreview();
            return;
        }

        const file = fileInput.files[0];
        if (validateFile(file)) {
            showFilePreview(file);
            if (scanButton) scanButton.disabled = false;
        } else {
            if (scanButton) scanButton.disabled = true;
            clearFilePreview();
        }
    }

    function validateFile(file) {
        if (file.size > MAX_FILE_SIZE) {
            showError(`File size exceeds 50MB limit (${formatFileSize(file.size)})`);
            return false;
        }

        if (!ALLOWED_TYPES.includes(file.type)) {
            showError('Invalid file type. Please upload a PDF, Word document, text file, JSON, HTML, or image file.');
            return false;
        }

        return true;
    }

    function showFilePreview(file) {
        if (!filePreview) return;

        const fileInfo = filePreview.querySelector('.file-info');
        if (fileInfo) {
            fileInfo.innerHTML = `
                <div class="flex justify-between items-center text-gray-300">
                    <span class="font-medium">File Name:</span>
                    <span class="text-right">${file.name}</span>
                </div>
                <div class="flex justify-between items-center text-gray-300">
                    <span class="font-medium">Size:</span>
                    <span>${formatFileSize(file.size)}</span>
                </div>
                <div class="flex justify-between items-center text-gray-300">
                    <span class="font-medium">Type:</span>
                    <span>${file.type || 'Unknown'}</span>
                </div>
            `;
        }
        filePreview.classList.remove('hidden');
    }

    function clearFilePreview() {
        if (!filePreview) return;
        const fileInfo = filePreview.querySelector('.file-info');
        if (fileInfo) {
            fileInfo.innerHTML = '';
        }
        filePreview.classList.add('hidden');
    }

    function showError(message) {
        if (!errorDisplay) return;
        errorDisplay.innerHTML = `
            <div class="bg-red-900/20 border border-red-500/50 rounded-lg p-4 mb-4">
                <div class="flex items-center">
                    <svg class="w-5 h-5 text-red-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span class="text-red-400">${message}</span>
                </div>
            </div>
        `;
        errorDisplay.classList.remove('hidden');
    }

    function clearError() {
        if (!errorDisplay) return;
        errorDisplay.classList.add('hidden');
    }

    function showUploadStatus(message) {
        if (!uploadStatus) return;
        uploadStatus.innerHTML = `
            <div class="flex items-center justify-center space-x-3">
                <div class="animate-spin rounded-full h-5 w-5 border-2 border-blue-500 border-t-transparent"></div>
                <span class="text-blue-400">${message}</span>
            </div>
        `;
        uploadStatus.classList.remove('hidden');
    }

    function hideUploadStatus() {
        if (!uploadStatus) return;
        uploadStatus.classList.add('hidden');
        uploadStatus.innerHTML = '';
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function displayScanResults(results) {
        let resultsContainer = document.getElementById('scan-results');
        if (!resultsContainer) {
            resultsContainer = document.createElement('div');
            resultsContainer.id = 'scan-results';
            fileForm.appendChild(resultsContainer);
        }

        const riskColor = results.riskScore <= 30 ? 'green' : results.riskScore <= 70 ? 'yellow' : 'red';
        
        resultsContainer.innerHTML = `
            <div class="bg-gray-800 rounded-lg p-6 mt-6 border border-gray-700">
                <h3 class="text-xl font-bold text-white mb-4">Scan Results</h3>
                
                <!-- Risk Score -->
                <div class="mb-6">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-gray-300">Risk Level:</span>
                        <span class="text-${riskColor}-500 font-bold">${results.riskLevel} (${results.riskScore}%)</span>
                    </div>
                    <div class="w-full h-2 bg-gray-700 rounded-full">
                        <div class="h-full rounded-full bg-${riskColor}-500 transition-all duration-500" 
                             style="width: ${results.riskScore}%"></div>
                    </div>
                </div>

                <!-- File Details -->
                <div class="grid grid-cols-2 gap-4 mb-6">
                    <div class="text-gray-300">
                        <span class="font-medium">File Name:</span>
                        <div class="text-white">${results.name}</div>
                    </div>
                    <div class="text-gray-300">
                        <span class="font-medium">Size:</span>
                        <div class="text-white">${results.sizeFormatted}</div>
                    </div>
                    <div class="text-gray-300">
                        <span class="font-medium">Type:</span>
                        <div class="text-white">${results.type}</div>
                    </div>
                    <div class="text-gray-300">
                        <span class="font-medium">Scan Time:</span>
                        <div class="text-white">${results.scanDuration}</div>
                    </div>
                </div>

                <!-- File Hash -->
                <div class="mb-6">
                    <span class="text-gray-300 font-medium">File Hash (SHA-256):</span>
                    <div class="text-white font-mono text-sm break-all mt-1">${results.hash}</div>
                </div>

                <!-- Threats Section -->
                ${results.threats.length > 0 ? `
                    <div class="bg-red-900/20 border border-red-500/50 rounded-lg p-4">
                        <h4 class="text-lg font-semibold text-red-400 mb-2">Detected Threats:</h4>
                        <ul class="list-disc list-inside space-y-1">
                            ${results.threats.map(threat => `
                                <li class="text-red-300">${threat}</li>
                            `).join('')}
                        </ul>
                    </div>
                ` : `
                    <div class="bg-green-900/20 border border-green-500/50 rounded-lg p-4">
                        <div class="flex items-center">
                            <svg class="w-5 h-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                            </svg>
                            <span class="text-green-400 font-medium">No threats detected</span>
                        </div>
                    </div>
                `}
            </div>
        `;

        resultsContainer.classList.remove('hidden');
        resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }
}); 