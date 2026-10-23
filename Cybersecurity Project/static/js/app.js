/**
 * SecureScan — Client-Side Controller
 * Handles animated scan progress states, interactive finding filters,
 * client-side pre-validation, and confirmation modals.
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Scan Form Submission & Loading State
    const scanForm = document.getElementById("scan-form");
    const scanButton = document.getElementById("start-scan-btn");
    const loadingOverlay = document.getElementById("scan-loading-overlay");
    const urlInput = document.getElementById("target_url");
    const authCheckbox = document.getElementById("auth_confirm");

    if (scanForm && scanButton) {
        scanForm.addEventListener("submit", (e) => {
            if (!authCheckbox.checked) {
                e.preventDefault();
                alert("Authorization Confirmation Required:\nPlease confirm that you have permission to test this target before proceeding.");
                authCheckbox.focus();
                return;
            }

            const targetVal = urlInput.value.trim();
            if (!targetVal.startsWith("http://") && !targetVal.startsWith("https://")) {
                e.preventDefault();
                alert("Invalid Protocol:\nURL must begin explicitly with http:// or https://");
                urlInput.focus();
                return;
            }

            // Display loading overlay
            if (loadingOverlay) {
                loadingOverlay.style.display = "block";
            }
            scanButton.disabled = true;
            scanButton.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Auditing Security Configuration...`;
        });
    }

    // 2. Interactive Severity Filter Tabs on Results Page
    const filterButtons = document.querySelectorAll(".filter-btn");
    const findingItems = document.querySelectorAll(".finding-item");

    if (filterButtons.length > 0) {
        filterButtons.forEach((btn) => {
            btn.addEventListener("click", () => {
                // Update active button state
                filterButtons.forEach((b) => b.classList.remove("active", "btn-cyan"));
                filterButtons.forEach((b) => b.classList.add("btn-outline-cyan"));
                btn.classList.add("active", "btn-cyan");
                btn.classList.remove("btn-outline-cyan");

                const targetSev = btn.getAttribute("data-filter");

                findingItems.forEach((item) => {
                    const itemSev = item.getAttribute("data-severity");
                    if (targetSev === "all" || itemSev === targetSev) {
                        item.style.display = "block";
                    } else {
                        item.style.display = "none";
                    }
                });
            });
        });
    }

    // 3. Clear History Confirmation
    const clearHistoryBtn = document.getElementById("clear-history-btn");
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener("click", (e) => {
            if (!confirm("Are you sure you want to clear your local scan history? This action cannot be undone.")) {
                e.preventDefault();
            }
        });
    }
});
