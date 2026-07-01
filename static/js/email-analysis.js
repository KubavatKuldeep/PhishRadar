/* PhishRadar - Email Analysis Engine */

async function executeEmailForensics(event) {
    event.preventDefault();
    const sender = document.getElementById('senderInput').value.trim();
    const subject = document.getElementById('subjectInput').value.trim();
    const body = document.getElementById('bodyInput').value.trim();

    if (!sender || !body) {
        alert('Sender and body fields are required.');
        return;
    }

    // Show loader
    document.getElementById('emailStaticPlaceholder').classList.add('d-none');
    document.getElementById('emailAnalysisInteractiveView').classList.add('d-none');
    document.getElementById('emailProcessingLoader').classList.remove('d-none');
    document.getElementById('emailSubmitBtn').disabled = true;

    try {
        const response = await fetch(`${BACKEND_URL}/analyze-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sender, subject, body })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Server error occurred');
        }

        const data = await response.json();

        // Hide loader, show results
        document.getElementById('emailProcessingLoader').classList.add('d-none');
        document.getElementById('emailAnalysisInteractiveView').classList.remove('d-none');
        document.getElementById('emailSubmitBtn').disabled = false;

        // Risk score
        const scoreEl = document.getElementById('renderedEmailScore');
        scoreEl.innerText = `${data.risk_score}/100`;
        if (data.risk_score <= 30) {
            scoreEl.className = 'h4 fw-bold text-success d-block mb-0';
        } else if (data.risk_score <= 60) {
            scoreEl.className = 'h4 fw-bold text-warning d-block mb-0';
        } else {
            scoreEl.className = 'h4 fw-bold text-danger d-block mb-0';
        }

        // Threat level
        document.getElementById('renderedEmailLabel').innerText = getThreatLabel(data.risk_score);

        // Threat indicator badges
        const badgeBox = document.getElementById('emailIndicatorsContainer');
        badgeBox.innerHTML = '';
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

        const getBadgeColor = (weight) => {
            if (weight >= 30) return 'border-danger text-danger';
            if (weight >= 20) return 'border-warning text-warning';
            return 'border-info text-info';
        };

        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(finding => {
                const weight = findingWeights[finding] || 10;
                const colorClass = getBadgeColor(weight);
                badgeBox.innerHTML += `
                    <span class="badge bg-secondary border ${colorClass} small me-1 px-2 py-1">
                        ${finding}
                    </span>`;
            });
        } else {
            badgeBox.innerHTML = `
                <span class="badge bg-secondary border border-success text-success small px-2 py-1">
                    No Threats Detected
                </span>`;
        }

        // Show quota note if AI failed
        if (data.quota_exceeded) {
            showQuotaNote('emailErrorContainer');
        }

        // Sender domain analysis
        const senderDomain = sender.includes('@') ? sender.split('@')[1] : sender;
        const senderHasSuspicious = data.findings.some(f =>
            f === 'Suspicious Sender Domain' ||
            f === 'Brand Impersonation Flags' ||
            f === 'Free Email Provider Used'
        );
        const senderDomainNode = document.getElementById('senderDomainAnalysisNode');
        senderDomainNode.innerHTML = `
            <span class="text-white">Domain: </span>
            <span class="text-info">${senderDomain}</span>
            <span class="ms-3 badge ${senderHasSuspicious ? 'badge-danger' : 'badge-safe'}">
                ${senderHasSuspicious ? 'Suspicious' : 'Looks Clean'}
            </span>
        `;

        // Extracted URLs
        const extractedLinkNode = document.getElementById('extractedEmailLinkNode');
        if (data.urls_found && data.urls_found.length > 0) {
            extractedLinkNode.innerHTML = data.urls_found.map(url =>
                `<div class="text-truncate text-info">${url}</div>`
            ).join('');
        } else {
            extractedLinkNode.innerText = 'No URLs found in email body';
        }

        // AI explanation
        document.getElementById('emailAiExplanationContainer').innerText =
            data.ai_explanation || 'No AI explanation available.';

        // Build chain for dashboard
        const chainForDashboard = [
            { id: '1', title: 'Sender Address', data: sender },
            { id: '2', title: 'Subject Line', data: subject || '(No Subject)' },
            ...(data.urls_found && data.urls_found.length > 0
                ? data.urls_found.map((url, index) => ({
                    id: String(index + 3),
                    title: index === 0 ? 'Malicious URL Found' : `Malicious URL ${index + 1}`,
                    data: url
                }))
                : [{ id: '3', title: 'No Malicious URLs', data: 'No links found in body' }]
            )
        ];

        // Build findings for dashboard
        const findingsForDashboard = data.findings.map(finding => ({
            check: finding,
            status: getThreatLabel(data.risk_score),
            score: data.risk_score
        }));

        // Save to localStorage for dashboard
        const telemetryPayload = {
            vectorType: 'Email Forensic Inspection',
            targetName: subject || '(No Subject)',
            calculatedScore: data.risk_score,
            explanations: data.ai_explanation || 'No AI explanation available.',
            recommendations: data.recommendations || [],
            chain: chainForDashboard,
            findings: findingsForDashboard,
            senderInfo: {
                address: sender,
                domain: senderDomain,
                isSuspicious: senderHasSuspicious,
                reasons: data.findings.filter(f =>
                    f === 'Suspicious Sender Domain' ||
                    f === 'Brand Impersonation Flags' ||
                    f === 'Free Email Provider Used'
                )
            }
        };

        localStorage.setItem('activeTelemetryPayload', JSON.stringify(telemetryPayload));

    } catch (error) {
        document.getElementById('emailProcessingLoader').classList.add('d-none');
        document.getElementById('emailStaticPlaceholder').classList.remove('d-none');
        document.getElementById('emailSubmitBtn').disabled = false;
        showError('emailErrorContainer', `Analysis failed: ${error.message}`);
    }
}

function routeToGlobalDashboard(type) {
    window.location.href = 'results.html';
}