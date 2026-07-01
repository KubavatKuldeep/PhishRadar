/**
 * PhishRadar - Core Global Utilities & Engine
 */
const BACKEND_URL = window.location.origin;

document.addEventListener('DOMContentLoaded', () => {
    // Keyboard Accessibility Support
    const interactiveElements = document.querySelectorAll('.cyber-card, .btn-cyber-primary, .btn-cyber-secondary');
    interactiveElements.forEach(el => {
        if (!el.hasAttribute('tabindex')) {
            el.setAttribute('tabindex', '0');
        }
    });
});

// Utility function to compute Threat Color Palette mappings programmatically
function getThreatColor(score) {
    if (score < 30) return '#00C853'; // Success/Safe
    if (score < 60) return '#FFC107'; // Warning/Suspicious
    return '#FF5252';                // Danger/Dangerous
}

// Global threat lookup string conversion
function getThreatLabel(score) {
    if (score < 30) return 'Safe';
    if (score < 60) return 'Suspicious';
    return 'Dangerous';
}

function getThreatBadgeClass(score) {
    if (score < 30) return 'badge-safe';
    if (score < 60) return 'badge-suspicious';
    return 'badge-danger';
}
function routeToGlobalDashboard(type) {
    window.location.href = 'results.html';
}
function showError(containerId, message) {
    const container = document.getElementById(containerId);
    if (!container) {
        alert(message);
        return;
    }
    container.innerHTML = `
        <div class="cyber-alert-error mt-3">
            <i class="fa-solid fa-circle-exclamation fa-lg"></i>
            <span>${message}</span>
        </div>
    `;
    setTimeout(() => {
        if (container) container.innerHTML = '';
    }, 5000);
}

function showQuotaNote(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = `
        <div class="cyber-alert-error mt-3" style="border-color: var(--status-warning); color: var(--status-warning); background-color: rgba(255,193,7,0.1);">
            <i class="fa-solid fa-triangle-exclamation fa-lg"></i>
            <span><strong>Note:</strong> This academic prototype runs on a free-tier Google AI Studio API allocation. If AI insights return structural telemetry instead of a narrative breakdown, the shared project quota limits have been temporarily exceeded by other evaluators.</span>
        </div>
    `;
}

function showSuccess(containerId, message) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = `
        <div class="cyber-alert-success mt-3">
            <i class="fa-solid fa-circle-check fa-lg"></i>
            <span>${message}</span>
        </div>
    `;
    setTimeout(() => {
        if (container) container.innerHTML = '';
    }, 4000);
}