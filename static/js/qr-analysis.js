/* PhishRadar - QR Analysis Engine */

function triggerManualQrFileSelection() {
    document.getElementById('hiddenQrFileInput').click();
}

function processQrImageUpload(file) {
    if (!file) return;
    const fileReaderInstance = new FileReader();
    fileReaderInstance.onload = function(e) {
        document.getElementById('qrTargetImagePreviewElement').src = e.target.result;
        document.getElementById('qrAssetPreviewBox').classList.remove('d-none');
    };
    fileReaderInstance.readAsDataURL(file);
}

document.addEventListener('DOMContentLoaded', () => {
    const dropZoneNode = document.querySelector('.drag-drop-zone');
    if (!dropZoneNode) return;

    dropZoneNode.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZoneNode.classList.add('dragover');
    });

    dropZoneNode.addEventListener('dragleave', () => {
        dropZoneNode.classList.remove('dragover');
    });

    dropZoneNode.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZoneNode.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            processQrImageUpload(e.dataTransfer.files[0]);
        }
    });
});

async function runQrForensicDeconstruction() {
    const fileInput = document.getElementById('hiddenQrFileInput');
    if (!fileInput.files || fileInput.files.length === 0) {
        alert('Please upload a QR code image first.');
        return;
    }

    const file = fileInput.files[0];

    // Show loader
    document.getElementById('qrEngineDefaultPlaceholder').classList.add('d-none');
    document.getElementById('qrEngineInteractiveResultsDashboard').classList.add('d-none');
    document.getElementById('qrEngineLoadingIndicator').classList.remove('d-none');
    document.getElementById('qrTriggerProcessBtn').disabled = true;

    try {
        const formData = new FormData();
        formData.append('image', file);

        const response = await fetch(`${BACKEND_URL}/analyze-qr`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Server error occurred');
        }

        const data = await response.json();

        // Hide loader, show results
        document.getElementById('qrEngineLoadingIndicator').classList.add('d-none');
        document.getElementById('qrEngineInteractiveResultsDashboard').classList.remove('d-none');
        document.getElementById('qrTriggerProcessBtn').disabled = false;

        // Risk score with color
        const scoreEl = document.getElementById('qrRenderedScore');
        scoreEl.innerText = `${data.risk_score}/100`;
        if (data.risk_score <= 30) {
            scoreEl.className = 'h4 fw-bold text-success';
        } else if (data.risk_score <= 60) {
            scoreEl.className = 'h4 fw-bold text-warning';
        } else {
            scoreEl.className = 'h4 fw-bold text-danger';
        }

        // Show quota note if AI failed
        if (data.quota_exceeded) {
            showQuotaNote('qrErrorContainer');
        }
        
        // Decoded URL
        const decodedUrl = data.decoded_url || 'No URL found in QR code';
        document.getElementById('qrRenderedPayloadString').innerText = decodedUrl;

        // AI explanation
        document.getElementById('qrAiExplanationViewField').innerText =
            data.ai_explanation || 'No AI explanation available.';

        // Findings list
        const findingsUl = document.getElementById('qrFindingsBulletContainer');
        findingsUl.innerHTML = '';
        const findingWeights = {
            "No HTTPS": 20,
            "IP Address URL Detected": 25,
            "URL Shortener Detected": 10,
            "Suspicious Keyword Detected": 15,
            "Excessive Subdomains Detected": 15,
            "Brand Impersonation Flags": 30,
            "Urgent Language Detected": 20,
            "Multiple Redirection Hops": 15,
            "Suspicious Sender Domain": 20,
            "Free Email Provider Used": 10,
            "URL Authority Spoofing Detected": 35,
            "Suspicious TLD Detected": 20,
            "Hyphen Abuse in Domain": 10,
            "Digits in Domain Name": 10
        };

        const iconMap = {
            'No HTTPS': 'fa-lock-open',
            'Brand Impersonation Flags': 'fa-building-shield',
            'Suspicious Keyword Detected': 'fa-magnifying-glass',
            'URL Shortener Detected': 'fa-link',
            'Multiple Redirection Hops': 'fa-route',
            'Excessive Subdomains Detected': 'fa-diagram-next',
            'IP Address URL Detected': 'fa-network-wired',
            'URL Authority Spoofing Detected': 'fa-user-secret',
            'Suspicious TLD Detected': 'fa-globe',
            'Hyphen Abuse in Domain': 'fa-minus',
            'Digits in Domain Name': 'fa-hashtag'
        };

        const getSeverityColor = (weight) => {
            if (weight >= 30) return 'text-danger';
            if (weight >= 20) return 'text-warning';
            return 'text-info';
        };

        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(finding => {
                const weight = findingWeights[finding] || 10;
                const icon = iconMap[finding] || 'fa-triangle-exclamation';
                const color = getSeverityColor(weight);
                findingsUl.innerHTML += `
                    <li class="list-group-item bg-transparent border-secondary small d-flex align-items-center justify-content-between">
                        <div class="d-flex align-items-center">
                            <i class="fa-solid ${icon} ${color} me-3" style="width: 20px;"></i>
                            <span class="text-white fw-semibold">${finding}</span>
                        </div>
                        <span class="badge ${weight >= 30 ? 'badge-danger' : weight >= 20 ? 'badge-suspicious' : 'badge-safe'} ms-2">
                            +${weight} pts
                        </span>
                    </li>
                `;
            });
        } else {
            findingsUl.innerHTML = `
                <li class="list-group-item bg-transparent border-secondary small d-flex align-items-center">
                    <i class="fa-solid fa-circle-check text-success me-3" style="width: 20px;"></i>
                    <span class="text-success fw-semibold">No threats detected — QR code appears safe</span>
                </li>
            `;
        }

        // Build chain for dashboard
        const chainForDashboard = data.redirect_chain && data.redirect_chain.length > 0
            ? data.redirect_chain.map((url, index) => ({
                id: String(index + 1),
                title: index === 0 ? 'QR Decoded URL' :
                       index === data.redirect_chain.length - 1 ? 'Final Destination' :
                       `Redirect Hop ${index}`,
                data: url
            }))
            : [{ id: '1', title: 'QR Decoded Content', data: decodedUrl }];

        // Build findings for dashboard
        const findingsForDashboard = (data.findings || []).map(finding => ({
            check: finding,
            status: getThreatLabel(data.risk_score),
            score: data.risk_score
        }));

        // Save to localStorage for dashboard
        const telemetryPayload = {
            vectorType: 'QR Code Matrix Deconstruction',
            targetName: decodedUrl,
            calculatedScore: data.risk_score,
            explanations: data.ai_explanation || 'No AI explanation available.',
            recommendations: data.recommendations || [],
            chain: chainForDashboard,
            findings: findingsForDashboard
        };

        localStorage.setItem('activeTelemetryPayload', JSON.stringify(telemetryPayload));

    } catch (error) {
        document.getElementById('qrEngineLoadingIndicator').classList.add('d-none');
        document.getElementById('qrEngineDefaultPlaceholder').classList.remove('d-none');
        document.getElementById('qrTriggerProcessBtn').disabled = false;
        showError('qrErrorContainer', `Analysis failed: ${error.message}`);
    }
}

function routeToGlobalDashboard(type) {
    window.location.href = 'results.html';
}