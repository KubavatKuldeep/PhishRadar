/**
 * PhishRadar- Results Dashboard View Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    // Generate a random session tracking identifier string for display authenticity
    const generatedHash = 'PR-SESSION-' + Math.floor(100000 + Math.random() * 900000);
    const hashElement = document.getElementById('randomSessionHashString');
    if (hashElement) hashElement.innerText = generatedHash;

    // Check for cached threat telemetry data from previously run modules
    const operationalJsonPayload = localStorage.getItem('activeTelemetryPayload');

    if (operationalJsonPayload) {
        const payload = JSON.parse(operationalJsonPayload);
        bindTelemetryPayloadToDashboard(payload);
    } else {
        document.getElementById('dashboardRiskTextScoreOutput').innerText = '--';
        document.getElementById('dashboardTargetLabelTitle').innerText = 'No Scan Loaded Yet';
        document.getElementById('dashboardAiTextExplanationBlock').innerText =
            'No analysis data found. Please run a URL, Email, or QR scan first, then return here to view your full threat report.';
        document.getElementById('dashboardThreatLevelClassificationBadge').innerText = 'No Data';
        document.getElementById('dashboardThreatLevelClassificationBadge').className =
            'badge px-3 py-2 fs-6 fw-bold text-uppercase badge-suspicious';
        return;
    }
});

function bindTelemetryPayloadToDashboard(payload) {
    // 1. Text Field bindings
    document.getElementById('dashboardVectorLabelField').innerText = payload.vectorType;
    document.getElementById('dashboardTargetLabelTitle').innerText = payload.targetName;

    // Technical Breakdown Card
    const breakdownGrid = document.getElementById('technicalBreakdownGrid');
    if (breakdownGrid && payload.targetName) {
        const targetUrl = payload.targetName;
        let techItems = [];

        try {
            const parsed = new URL(targetUrl);
            const hostname = parsed.hostname;
            const domainParts = hostname.split('.');
            const tld = '.' + domainParts[domainParts.length - 1];
            const subdomainDepth = domainParts.length - 2;
            const pathDepth = parsed.pathname.split('/').filter(p => p).length;
            const urlLength = targetUrl.length;
            const domainLength = hostname.length;
            const protocol = parsed.protocol.replace(':', '').toUpperCase();
            const keywordCount = payload.findings
                ? payload.findings.filter(f => f === 'Suspicious Keyword Detected').length
                : 0;
            const findingsCount = payload.findings ? payload.findings.length : 0;

            techItems = [
                { label: 'URL Length', value: `${urlLength} chars`, color: urlLength > 75 ? 'text-warning' : 'text-success' },
                { label: 'Protocol', value: protocol, color: protocol === 'HTTPS' ? 'text-success' : 'text-danger' },
                { label: 'TLD', value: tld, color: ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click'].includes(tld) ? 'text-danger' : 'text-success' },
                { label: 'Subdomain Depth', value: subdomainDepth, color: subdomainDepth > 2 ? 'text-warning' : 'text-success' },
                { label: 'Path Depth', value: pathDepth, color: 'text-info' },
                { label: 'Domain Length', value: `${domainLength} chars`, color: domainLength > 20 ? 'text-warning' : 'text-success' },
                { label: 'Risk Findings', value: `${findingsCount} found`, color: findingsCount > 0 ? 'text-danger' : 'text-success' },
                { label: 'Threat Level', value: payload.calculatedScore <= 30 ? 'Safe' : payload.calculatedScore <= 60 ? 'Suspicious' : 'Dangerous', color: payload.calculatedScore <= 30 ? 'text-success' : payload.calculatedScore <= 60 ? 'text-warning' : 'text-danger' }
            ];
        } catch (e) {
            // Not a URL (email subject etc) — show basic info
            techItems = [
                { label: 'Vector Type', value: payload.vectorType, color: 'text-info' },
                { label: 'Risk Score', value: `${payload.calculatedScore}/100`, color: payload.calculatedScore <= 30 ? 'text-success' : payload.calculatedScore <= 60 ? 'text-warning' : 'text-danger' },
                { label: 'Findings Count', value: payload.findings ? payload.findings.length : 0, color: 'text-info' },
                { label: 'Threat Level', value: getThreatLabel(payload.calculatedScore), color: payload.calculatedScore <= 30 ? 'text-success' : payload.calculatedScore <= 60 ? 'text-warning' : 'text-danger' }
            ];
        }

        breakdownGrid.innerHTML = techItems.map(item => `
            <div class="col-6 col-md-4 col-lg-3">
                <div class="p-3 rounded bg-dark border border-secondary text-center h-100">
                    <span class="d-block text-muted-custom small mb-1">${item.label}</span>
                    <span class="fw-bold ${item.color}">${item.value}</span>
                </div>
            </div>
        `).join('');
    }

    // Show domain analysis card only for email scans
    const domainCard = document.getElementById('emailDomainAnalysisCard');
    if (payload.vectorType === 'Email Forensic Inspection' && payload.senderInfo) {
        domainCard.classList.remove('d-none');

        document.getElementById('domainSenderAddress').innerText = payload.senderInfo.address;
        document.getElementById('domainSenderDomain').innerText = payload.senderInfo.domain;

        const verdictEl = document.getElementById('domainVerdict');
        if (payload.senderInfo.isSuspicious) {
            verdictEl.innerText = 'Suspicious Domain';
            verdictEl.className = 'fw-bold text-danger';
        } else {
            verdictEl.innerText = 'Domain Looks Clean';
            verdictEl.className = 'fw-bold text-success';
        }

        // Build explanation of why domain is suspicious
        let whyText = '';
        if (payload.senderInfo.reasons.length === 0) {
            whyText = 'No specific domain-level threats detected. Always verify sender identity through official channels.';
        } else {
            const reasonMap = {
                'Brand Impersonation Flags': 'The domain contains a known brand name but does not match the official domain. This is a classic phishing tactic where attackers use domains like "paypal-security.com" instead of "paypal.com" to deceive recipients.',
                'Suspicious Sender Domain': 'The sender domain contains suspicious keywords like "secure", "verify", "update" or "support" which are commonly used by phishing campaigns to appear legitimate.',
                'Free Email Provider Used': 'A free email provider was used to impersonate an official organization. Legitimate companies always use their own corporate email domain.'
            };
            whyText = payload.senderInfo.reasons
                .map(r => reasonMap[r] || r)
                .join(' ');
        }
        document.getElementById('domainWhySuspicious').innerText = whyText;
    } else {
        domainCard.classList.add('d-none');
    }
    const aiText = payload.explanations || '';
    const isQuotaExceeded = payload.quota_exceeded || aiText === 'AI insights unavailable.';
    document.getElementById('dashboardAiTextExplanationBlock').innerText = aiText || 'No AI explanation available.';

    if (isQuotaExceeded) {
        const aiCard = document.getElementById('dashboardAiTextExplanationBlock').closest('.cyber-card');
        const noteDiv = document.createElement('div');
        noteDiv.className = 'cyber-alert-error mt-3';
        noteDiv.style.borderColor = 'var(--status-warning)';
        noteDiv.style.color = 'var(--status-warning)';
        noteDiv.style.backgroundColor = 'rgba(255,193,7,0.1)';
        noteDiv.innerHTML = `
            <i class="fa-solid fa-triangle-exclamation fa-lg"></i>
            <span><strong>Note:</strong> This academic prototype runs on a free-tier Google AI Studio API allocation. If AI insights return structural telemetry instead of a narrative breakdown, the shared project quota limits have been temporarily exceeded by other evaluators.</span>
        `;
        aiCard.appendChild(noteDiv);
    }
    document.getElementById('dashboardRiskTextScoreOutput').innerText = payload.calculatedScore;

    // 2. Compute dynamic severity labels based on computed score
    const targetLabel = getThreatLabel(payload.calculatedScore);
    const targetBadgeClass = getThreatBadgeClass(payload.calculatedScore);
    const primaryClassificationColor = getThreatColor(payload.calculatedScore);

    const classificationBadge = document.getElementById('dashboardThreatLevelClassificationBadge');
    classificationBadge.className = `badge px-3 py-2 fs-6 fw-bold text-uppercase ${targetBadgeClass}`;
    classificationBadge.innerText = targetLabel;

    // 3. Animate Circle Circumference Math Formulas Gauge
    const circleGauge = document.getElementById('dashboardRiskCircleFillGauge');
    circleGauge.style.stroke = primaryClassificationColor;
    
    // Circumference of Radius 85 is ~534px. Offset calculation:
    const circumference = 534;
    const computedOffset = circumference - ((payload.calculatedScore / 100) * circumference);
    
    // Apply layout change using dynamic micro-task intervals
    setTimeout(() => {
        circleGauge.style.strokeDashoffset = computedOffset;
    }, 250);

    // 4. Construct Multi-Hop Pipeline Redirect Chain View Elements
    const pipeContainer = document.getElementById('dashboardRoutingChainRowContainer');
    pipeContainer.innerHTML = '';

    payload.chain.forEach((hop, index) => {
        pipeContainer.innerHTML += `
            <div class="col">
                <div class="p-3 rounded bg-dark border border-secondary flow-node h-100 d-flex flex-column justify-content-center">
                    <span class="d-block text-info extra-small fw-bold text-uppercase mb-1" style="font-size:0.75rem;">Hop ${hop.id}</span>
                    <h4 class="h6 text-white mb-1 fw-bold text-truncate">${hop.title}</h4>
                    <span class="text-muted-custom small text-truncate d-block" title="${hop.data}">${hop.data}</span>
                </div>
            </div>
        `;
        // Inject connecting arrows between nodes in standard multi-row configurations
        if (index < payload.chain.length - 1) {
            pipeContainer.innerHTML += `
                <div class="col-12 d-lg-none flow-arrow-container py-1">
                    <i class="fa-solid fa-arrow-down-long"></i>
                </div>
                <div class="d-none d-lg-flex col flow-arrow-container" style="max-width: 40px; margin: 0 -10px;">
                    <i class="fa-solid fa-arrow-right-long"></i>
                </div>
            `;
        }
    });

    // 5. Generate Subsystem Diagnostics Rows Matrix
    const tableBody = document.getElementById('dashboardMetricsMatrixTableContent');
    tableBody.innerHTML = '';

    if (!payload.findings || payload.findings.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="2" class="text-muted-custom text-center py-4">No findings detected</td></tr>`;
    } else {
        // Individual finding weights for proper per-finding severity
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

        const severityLabel = (weight) => {
            if (weight >= 30) return { label: 'Critical', cls: 'badge-danger' };
            if (weight >= 20) return { label: 'High', cls: 'badge-suspicious' };
            if (weight >= 10) return { label: 'Medium', cls: 'badge-safe' };
            return { label: 'Low', cls: 'badge-safe' };
        };

        payload.findings.forEach(node => {
            const label = node.check || node.title || 'Unknown Check';
            const weight = findingWeights[label] || 10;
            const severity = severityLabel(weight);
            tableBody.innerHTML += `
                <tr>
                    <td class="text-white fw-semibold small">
                        <i class="fa-solid fa-square-rss text-info me-2"></i>${label}
                    </td>
                    <td>
                        <span class="badge ${severity.cls}">${severity.label}</span>
                    </td>
                    <td class="text-muted-custom small">
                        +${weight} pts
                    </td>
                </tr>
            `;
        });
    }

    // 6. Generate Dynamic Defensive Remediation Actions Guidance Checklists
    const proceduralBox = document.getElementById('dashboardRemediationStepsHolder');
    proceduralBox.innerHTML = '';

    let structuralSteps = [];
    if (payload.calculatedScore < 40) {
        structuralSteps = [
            { icon: 'fa-square-check', color: 'text-success', title: 'Log Inbound Metric In Baseline Trace', desc: 'No malicious indicators triggered during runtime payload evaluation parameters.' },
            { icon: 'fa-envelope-shield', color: 'text-success', title: 'Release Asset Destination Path', desc: 'Pass data packages seamlessly directly into client interface execution frames.' }
        ];
    } else if (payload.calculatedScore < 75) {
        structuralSteps = [
            { icon: 'fa-circle-exclamation', color: 'text-warning', title: 'Enforce Endpoint Sandbox Restrictions', desc: 'Isolate user session frames within segmented secure runtime micro-environments.' },
            { icon: 'fa-envelope-open-text', color: 'text-warning', title: 'Verify Sender Identity Manually', desc: 'Cross-reference envelope metadata with verified corporate address book entries.' }
        ];
    } else {
        structuralSteps = [
            { icon: 'fa-ban', color: 'text-danger', title: 'Terminate Network Ingress Routing', desc: 'Instantly isolate targeted assets and apply broad IP firewalls across corporate proxy tiers.' },
            { icon: 'fa-fingerprint', color: 'text-danger', title: 'Revoke Existing User Authentication Sessions', desc: 'Invalidate active tracking tokens immediately to mitigate credential phishing exposure.' },
            { icon: 'fa-bell', color: 'text-danger', title: 'Escalate Incident Ticket to Tier-2 SOC Response', desc: 'Transmit collected telemetry payload arrays directly into corporate logging registers.' }
        ];
    }

    // Use real AI recommendations if available
    if (payload.recommendations && payload.recommendations.length > 0) {
        payload.recommendations.forEach(rec => {
            proceduralBox.innerHTML += `
                <div class="d-flex align-items-start p-3 rounded bg-dark border border-secondary">
                    <i class="fa-solid fa-shield-halved text-info fa-lg me-3 mt-1"></i>
                    <div>
                        <span class="text-muted-custom d-block mt-1" style="font-size: 0.85rem;">${rec}</span>
                    </div>
                </div>
            `;
        });
    } else {
        structuralSteps.forEach(step => {
            proceduralBox.innerHTML += `
                <div class="d-flex align-items-start p-3 rounded bg-dark border border-secondary">
                    <i class="fa-solid ${step.icon} ${step.color} fa-lg me-3 mt-1"></i>
                    <div>
                        <span class="text-white fw-semibold d-block small">${step.title}</span>
                        <span class="text-muted-custom d-block mt-1" style="font-size: 0.85rem;">${step.desc}</span>
                    </div>
                </div>
            `;
        });
    }
}