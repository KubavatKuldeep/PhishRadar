/* PhishRadar - URL Analysis Engine */


async function executeUrlAnalysis(event) {
    event.preventDefault();
    const urlInput = document.getElementById('targetUrlInput').value.trim();
    if (!urlInput) return;

    function isValidUrl(str) {
        try { new URL(str); return true; }
        catch { return false; }
    }

    if (!isValidUrl(urlInput)) {
        alert('Please enter a valid URL including http:// or https://');
        return;
    }

    document.getElementById('loadingStateBlock').classList.remove('d-none');
    document.getElementById('resultsSummaryBlock').classList.add('d-none');
    document.getElementById('submitBtn').disabled = true;

    try {
        const response = await fetch(`${BACKEND_URL}/analyze-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Server error occurred');
        }

        const data = await response.json();

        document.getElementById('loadingStateBlock').classList.add('d-none');
        document.getElementById('resultsSummaryBlock').classList.remove('d-none');
        document.getElementById('renderedTargetUrl').innerText = urlInput;

        // Build chain array for dashboard
        const chainForDashboard = data.redirect_chain.map((url, index) => ({
            id: String(index + 1),
            title: index === 0 ? 'Original URL' : index === data.redirect_chain.length - 1 ? 'Final Destination' : `Redirect Hop ${index}`,
            data: url
        }));

        // Build findings for dashboard
        const findingsForDashboard = data.findings.map(finding => ({
            check: finding,
            status: getThreatLabel(data.risk_score),
            score: data.risk_score
        }));

        const telemetryPayload = {
            vectorType: 'URL Analysis Scan',
            targetName: urlInput,
            calculatedScore: data.risk_score,
            explanations: data.ai_explanation || 'No AI explanation available.',
            recommendations: data.recommendations || [],
            chain: chainForDashboard,
            findings: findingsForDashboard,
            quota_exceeded: data.quota_exceeded || false
        };

        console.log('Telemetry payload:', telemetryPayload);

        localStorage.setItem('activeTelemetryPayload', JSON.stringify(telemetryPayload));

        // Show quota note if AI failed
        if (data.quota_exceeded) {
            showQuotaNote('urlErrorContainer');
        }
        
        // Populate results table
        const tableContent = document.getElementById('urlFindingsTableContent');
        tableContent.innerHTML = '';

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

        const getSeverity = (weight) => {
            if (weight >= 30) return { label: 'Critical', cls: 'badge-danger' };
            if (weight >= 20) return { label: 'High', cls: 'badge-suspicious' };
            return { label: 'Medium', cls: 'badge-safe' };
        };

        data.findings.forEach(finding => {
            const weight = findingWeights[finding] || 10;
            const severity = getSeverity(weight);
            tableContent.innerHTML += `
                <tr>
                    <td class="fw-semibold text-white">
                        <i class="fa-solid fa-circle-check text-info me-2 small"></i>${finding}
                    </td>
                    <td><span class="badge ${severity.cls}">${severity.label}</span></td>
                    <td class="text-muted-custom small">+${weight} pts</td>
                </tr>
            `;
        });

    } catch (error) {
        document.getElementById('loadingStateBlock').classList.add('d-none');
        showError('urlErrorContainer', `Analysis failed: ${error.message}`);
    } finally {
        document.getElementById('submitBtn').disabled = false;
    }
}

function routeToGlobalDashboard(type) {
    window.location.href = 'results.html';
}