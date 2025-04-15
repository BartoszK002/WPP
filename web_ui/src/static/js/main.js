let processes = [];
let filteredProcesses = [];
let lastSearchQuery = '';
let refreshIntervalId = null;
let currentSortColumn = 'name';
let sortDirection = 1;
let archFilter = 'all';
let protectionFilter = 'all';
let systemFilter = 'all';
let windowFilter = 'all';

// Compile regex once and cache it
let searchRegex = null;

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function createSearchRegex(searchText) {
    if (!searchText) return null;
    const escaped = escapeRegExp(searchText);
    return new RegExp(escaped, 'i'); // case-insensitive
}

let isInitialLoad = true;
let lastUpdateTime = 0;
const UPDATE_THRESHOLD = 500; // ms

function updateProcessList() {
    const now = Date.now();
    const loadingOverlay = document.querySelector('.loading-overlay');
    
    // Only show loading on initial load and if not already showing
    if (isInitialLoad && !loadingOverlay) {
        showLoading();
    }
    
    fetch('/api/processes')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const processesByPid = new Map(data.map(p => [p.pid, p]));
            const changes = new Set();
            
            // Check for changes
            if (processes.length > 0) {
                processes.forEach(oldProcess => {
                    const newProcess = processesByPid.get(oldProcess.pid);
                    if (!newProcess || 
                        newProcess.isProtected !== oldProcess.isProtected) {
                        changes.add(oldProcess.pid);
                    }
                });
                
                data.forEach(newProcess => {
                    const oldProcess = processes.find(p => p.pid === newProcess.pid);
                    if (!oldProcess) {
                        changes.add(newProcess.pid);
                    }
                });
            } else {
                // First load, mark all as changed
                data.forEach(p => changes.add(p.pid));
            }

            processes = data;
            
            // Only update DOM if there are changes or enough time has passed
            if (changes.size > 0 || (now - lastUpdateTime) > UPDATE_THRESHOLD) {
                applySearchAndSort();
                lastUpdateTime = now;
            }

            if (isInitialLoad) {
                hideLoading();
                isInitialLoad = false;
            }
        })
        .catch(error => {
            console.error('Error fetching processes:', error);
            hideLoading();
            isInitialLoad = false;
            showNotification('Failed to fetch process list', 'error');
        });
}

function applySearchAndSort() {
    const tbody = document.getElementById('processTable');
    
    // Apply filters first to work with smaller dataset
    filteredProcesses = processes;
    
    if (lastSearchQuery) {
        const searchLower = lastSearchQuery.toLowerCase();
        filteredProcesses = filteredProcesses.filter(process => {
            const name = process.name.toLowerCase();
            const pidStr = process.pid.toString();
            const pidHex = '0x' + process.pid.toString(16);
            return name.includes(searchLower) || 
                   pidStr.includes(searchLower) || 
                   pidHex.includes(searchLower);
        });
    }

    // Apply architecture filter
    if (archFilter !== 'all') {
        filteredProcesses = filteredProcesses.filter(process => 
            archFilter === 'x64' ? process.is64Bit : !process.is64Bit
        );
    }

    // Apply protection filter
    if (protectionFilter !== 'all') {
        filteredProcesses = filteredProcesses.filter(process => 
            protectionFilter === 'protected' ? process.isProtected : !process.isProtected
        );
    }

    // Apply system process filter
    if (systemFilter !== 'all') {
        filteredProcesses = filteredProcesses.filter(process => {
            const isSystemProcess = process.isSystemProcess;
            return systemFilter === 'system' ? isSystemProcess : !isSystemProcess;
        });
    }

    // Apply window filter
    if (windowFilter !== 'all') {
        filteredProcesses = filteredProcesses.filter(process => 
            windowFilter === 'visible' ? process.hasVisibleWindow : !process.hasVisibleWindow
        );
    }

    // Apply sorting
    const compareFn = getComparisonFunction(currentSortColumn);
    filteredProcesses.sort(compareFn);

    // Prepare all row content first
    const rowsHTML = filteredProcesses.map(process => {
        const iconHtml = process.icon ? 
            `<div class="process-icon">
                <img src="${process.icon}" 
                     alt="" 
                     onerror="console.error('Failed to load icon for process:', '${process.name}', this.src); this.style.display='none';"
                     onload="console.log('Successfully loaded icon for process:', '${process.name}');"
                />
             </div>` :
            `<div class="process-icon"></div>`;
        
        const statusIcon = process.isProtected ? 
            '<span class="status-icon status-protected"><i class="material-icons">security</i>Protected</span>' :
            '<span class="status-icon status-unprotected"><i class="material-icons">lock_open</i>Unprotected</span>';

        const archClass = process.is64Bit ? 'arch-x64' : 'arch-x86';
        const archIcon = `<span class="arch-icon ${archClass}"><i class="material-icons">memory</i>${process.is64Bit ? 'x64' : 'x86'}</span>`;
        
        const actionButtons = `
            ${process.isProtected ? 
                `<button class="unprotect-btn" onclick="unprotectProcess(${process.pid})">Unprotect</button>` : 
                `<button class="protect-btn" onclick="protectProcess(${process.pid})">Protect</button>`
            }`;
        
        return `<tr data-pid="${process.pid}">
            <td title="${process.name}">
                ${iconHtml}
                <span class="process-name" style="cursor:pointer" onclick="showProcessDetails(${process.pid})">${process.name}</span>
            </td>
            <td title="PID: ${process.pid}">${process.pid} (0x${process.pid.toString(16).toUpperCase()})</td>
            <td>${archIcon}</td>
            <td>${statusIcon}</td>
            <td>
                ${actionButtons}
            </td>
        </tr>`;
    }).join('');

    // Single DOM update
    tbody.innerHTML = rowsHTML;
}

function getComparisonFunction(column) {
    if (column === 'pid') {
        return (a, b) => (a.pid - b.pid) * sortDirection;
    }
    if (column === 'arch') {
        return (a, b) => (a.is64Bit === b.is64Bit ? 0 : a.is64Bit ? 1 : -1) * sortDirection;
    }
    if (column === 'protection') {
        return (a, b) => (a.isProtected === b.isProtected ? 0 : a.isProtected ? 1 : -1) * sortDirection;
    }
    // For name comparison
    return (a, b) => {
        const aVal = a[column].toLowerCase();
        const bVal = b[column].toLowerCase();
        return aVal.localeCompare(bVal) * sortDirection;
    };
}

function sortProcesses(column) {
    // Don't allow sorting the Actions column
    if (column === 'actions') {
        return;
    }

    if (currentSortColumn === column) {
        sortDirection *= -1;
    } else {
        sortDirection = 1;
        currentSortColumn = column;
    }

    // Update sort indicators
    document.querySelectorAll('th').forEach(header => {
        header.classList.remove('sorted', 'reverse');
        if (header.dataset.column === column) {
            header.classList.add('sorted');
            if (sortDirection === -1) {
                header.classList.add('reverse');
            }
        }
    });

    applySearchAndSort();
}

async function protectProcess(pid) {
    try {
        // Get process details first
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/protect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid: pid })
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification(
                `Process ${processInfo} protected successfully.`,
                'success'
            );
            
            await updateProcessList();
            
            if (activeProcessPid === pid) {
                await updateProcessDetails(pid);
            }
        } else {
            let errorMessage = `Failed to protect process ${processInfo}\n`;
            if (data.error) {
                errorMessage += `${data.error}\n`;
            }
            if (data.error_code) {
                errorMessage += `System Error Code: ${data.error_code}\n`;
            }
            if (data.error_details && data.error_details.trim()) {
                errorMessage += `${data.error_details.trim()}\n`;
            }
            showNotification(errorMessage.trim(), 'error');
        }
    } catch (error) {
        let errorMessage = `Network error while protecting process (PID: ${pid})\n`;
        errorMessage += `${error.message}`;
        showNotification(errorMessage, 'error');
    }
}

function showNotification(message, type = 'success') {
    // Remove any existing notification
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Create text node to prevent HTML injection and ensure proper encoding
    const messageText = document.createElement('pre');  
    messageText.className = 'notification-message';
    messageText.textContent = message;
    
    const closeButton = document.createElement('button');  
    closeButton.className = 'close-btn';
    closeButton.innerHTML = '&times;';  
    closeButton.setAttribute('aria-label', 'Close notification');
    closeButton.onclick = () => notification.remove();
    
    notification.appendChild(messageText);
    notification.appendChild(closeButton);
    document.body.appendChild(notification);

    // Auto-remove after 12 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 12000);
}

// Debounced search function
const debounce = (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
};

function startAutoRefresh() {
    if (refreshIntervalId) {
        clearInterval(refreshIntervalId);
    }
    
    const interval = parseInt(document.getElementById('refreshInterval').value);
    if (interval > 0) {
        refreshIntervalId = setInterval(updateProcessList, interval);
    }
}

// Add loading overlay
function showLoading() {
    if (!document.querySelector('.loading-overlay')) {
        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = '<div class="loading-spinner"></div>';
        document.body.appendChild(overlay);
    }
}

function hideLoading() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

// Add modal HTML to the page
const modalHtml = `
<div id="processDetailsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 id="modalTitle">Process Details</h2>
            <span class="close">&times;</span>
        </div>
        <div class="process-controls">
            <button id="btnTerminate" class="control-btn danger">
                <i class="material-icons">close</i>Terminate Process
            </button>
            <button id="btnSuspendResume" class="control-btn warning">
                <i class="material-icons">pause</i><span>Suspend Process</span>
            </button>
            <button id="btnViewModules" class="control-btn info">
                <i class="material-icons">list</i>View Modules
            </button>
        </div>
        <div id="processDetails">
            <table>
                <tr>
                    <td>PID</td>
                    <td id="detailPid"></td>
                </tr>
                <tr>
                    <td>Description</td>
                    <td id="detailDescription" class="expandable-cell">
                        <div class="text-content"></div>
                        <button class="expand-btn" onclick="toggleExpand(this)">Show More</button>
                    </td>
                </tr>
                <tr>
                    <td>Status</td>
                    <td id="detailStatus"></td>
                </tr>
                <tr><td>Username:</td><td id="detailUsername"></td></tr>
                <tr><td>CPU Usage:</td><td id="detailCpu"></td></tr>
                <tr><td>Memory Usage:</td><td id="detailMemory"></td></tr>
                <tr>
                    <td>Image Path:</td>
                    <td id="detailPath" class="expandable-cell">
                        <div class="text-content"></div>
                        <button class="expand-btn" onclick="toggleExpand(this)">Show More</button>
                    </td>
                </tr>
                <tr>
                    <td>Command Line:</td>
                    <td id="detailCmd" class="expandable-cell">
                        <div class="text-content"></div>
                        <button class="expand-btn" onclick="toggleExpand(this)">Show More</button>
                    </td>
                </tr>
                <tr><td>Architecture:</td><td id="detailArch"></td></tr>
                <tr><td>Protection:</td><td id="detailProtection"></td></tr>
                <tr id="peHeaderRow" style="display:none">
                    <td>PE Headers:</td>
                    <td>
                        <div id="peHeaderStatus">Unknown</div>
                        <div id="peHeaderControls" style="margin-top: 5px; display: flex; gap: 10px;">
                            <button id="btnEncryptPE" class="control-btn small-btn success">
                                <i class="material-icons">lock</i><span>Encrypt</span>
                            </button>
                            <button id="btnDecryptPE" class="control-btn small-btn warning">
                                <i class="material-icons">lock_open</i><span>Decrypt</span>
                            </button>
                        </div>
                    </td>
                </tr>
                <tr id="memoryScanRow" style="display:none">
                    <td>Memory Scan Detection:</td>
                    <td>
                        <div id="memoryScanStatus">Unknown</div>
                        <div id="memoryScanControls" style="margin-top: 5px; display: flex; gap: 10px;">
                            <button id="btnEnableMemoryScan" class="control-btn small-btn success">
                                <i class="material-icons">security</i><span>Enable</span>
                            </button>
                            <button id="btnDisableMemoryScan" class="control-btn small-btn warning">
                                <i class="material-icons">no_encryption</i><span>Disable</span>
                            </button>
                        </div>
                    </td>
                </tr>
                <tr id="antiTamperingRow" style="display:none">
                    <td>Anti-Tampering Protection:</td>
                    <td>
                        <div id="antiTamperingStatus">Unknown</div>
                        <div id="antiTamperingControls" style="margin-top: 5px; display: flex; gap: 10px;">
                            <button id="btnEnableAntiTampering" class="control-btn small-btn success">
                                <i class="material-icons">verified_user</i><span>Enable</span>
                            </button>
                            <button id="btnDisableAntiTampering" class="control-btn small-btn warning">
                                <i class="material-icons">block</i><span>Disable</span>
                            </button>
                        </div>
                    </td>
                </tr>
                <tr id="threadMonitoringRow" style="display:none">
                    <td>Thread Monitoring:</td>
                    <td>
                        <div id="threadMonitoringStatus">Unknown</div>
                        <div id="threadMonitoringControls" style="margin-top: 5px; display: flex; gap: 10px;">
                            <button id="btnEnableThreadMonitoring" class="control-btn small-btn success">
                                <i class="material-icons">visibility</i><span>Enable</span>
                            </button>
                            <button id="btnDisableThreadMonitoring" class="control-btn small-btn warning">
                                <i class="material-icons">visibility_off</i><span>Disable</span>
                            </button>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        <div class="resize-handle"></div>
    </div>
</div>

<div id="modulesModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 id="modulesTitle">Process Modules</h2>
            <span class="close">&times;</span>
        </div>
        <div class="modules-list">
            <table>
                <thead>
                    <tr>
                        <th data-sort="name">Name</th>
                        <th data-sort="baseAddress">Base Address</th>
                        <th data-sort="size">Size</th>
                        <th data-sort="description">Description</th>
                        <th data-sort="path">Path</th>
                    </tr>
                </thead>
                <tbody id="modulesList">
                </tbody>
            </table>
        </div>
        <div class="resize-handle"></div>
    </div>
</div>`;

// Add modal styles
const modalStyles = `
    .modal {
        display: none;
        position: fixed;
        z-index: 1000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0,0,0,0.4);
    }
    .modal-content {
        background-color: #1e1e1e;
        color: #ffffff;
        margin: 10% auto;
        padding: 0;
        border: 1px solid #333;
        width: 90%;
        max-width: 1080px;
        min-width: 400px;
        border-radius: 5px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        resize: both;
        overflow: auto;
        min-height: 300px;
        max-height: 80vh;
        position: relative;
    }
    .modal-header {
        padding: 15px 20px;
        background-color: #252525;
        border-bottom: 1px solid #333;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .close {
        color: #666;
        font-size: 28px;
        font-weight: bold;
        cursor: pointer;
        line-height: 24px;
    }
    .close:hover {
        color: #fff;
    }
    #processDetails {
        padding: 20px;
        overflow: auto;
    }
    #processDetails table {
        width: 100%;
        border-collapse: collapse;
    }
    #processDetails td {
        padding: 8px;
        border-bottom: 1px solid #333;
        vertical-align: top;
    }
    #processDetails td:first-child {
        font-weight: bold;
        width: 210px;
        color: #89d4ff;
        white-space: nowrap;
    }
    .expandable-cell {
        position: relative;
    }
    .expandable-cell .text-content {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 100%;
        transition: white-space 0.2s ease;
    }
    .expandable-cell.expanded .text-content {
        white-space: normal;
        word-break: break-all;
    }
    .expand-btn {
        background: #333;
        border: none;
        color: #89d4ff;
        padding: 2px 8px;
        margin-top: 4px;
        cursor: pointer;
        border-radius: 3px;
        font-size: 12px;
        display: none;
    }
    .expand-btn:hover {
        background: #444;
    }
    .expand-btn.visible {
        display: inline-block;
    }
    #modalTitle {
        color: #fff;
        margin: 0;
        font-size: 1.2em;
    }
    .process-controls {
        padding: 15px 20px;
        background-color: #252525;
        border-bottom: 1px solid #333;
        display: flex;
        gap: 10px;
    }
    .control-btn {
        background-color: #333;
        color: #fff;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 8px;
        transition: background-color 0.2s;
    }
    .control-btn.danger {
        background-color: #d32f2f;
    }
    .control-btn.danger:hover {
        background-color: #b71c1c;
    }
    .control-btn.warning {
        background-color: #f57c00;
    }
    .control-btn.warning:hover {
        background-color: #e65100;
    }
    .control-btn.info {
        background-color: #1976d2;
    }
    .control-btn.info:hover {
        background-color: #0d47a1;
    }
    .control-btn.success {
        background-color: #388e3c;
    }
    .control-btn.success:hover {
        background-color: #1b5e20;
    }
    .control-btn.small-btn {
        padding: 6px 12px;
        font-size: 0.9em;
        min-width: 90px;
        justify-content: center;
    }
    .control-btn.small-btn i {
        font-size: 16px;
        margin-right: 4px;
    }
    .resize-handle {
        position: absolute;
        bottom: 0;
        right: 0;
        width: 16px;
        height: 16px;
        cursor: nwse-resize;
        background: #333;
        clip-path: polygon(100% 0, 100% 100%, 0 100%);
    }
`;

// Add function to toggle expanded text
function toggleExpand(button) {
    const cell = button.parentElement;
    const wasExpanded = cell.classList.contains('expanded');
    cell.classList.toggle('expanded');
    button.textContent = wasExpanded ? 'Show More' : 'Show Less';
    checkTruncation();
}

// Function to check if content is truncated and show/hide expand button
function checkTruncation() {
    const expandableCells = document.querySelectorAll('.expandable-cell');
    expandableCells.forEach(cell => {
        const content = cell.querySelector('.text-content');
        const button = cell.querySelector('.expand-btn');
        const isExpanded = cell.classList.contains('expanded');
        
        // Save current state
        const wasScrollable = content.scrollWidth > content.clientWidth;
        
        // Temporarily remove ellipsis to check true width
        content.style.textOverflow = 'clip';
        const isScrollable = content.scrollWidth > content.clientWidth;
        content.style.textOverflow = 'ellipsis';
        
        if (isScrollable || isExpanded) {
            button.classList.add('visible');
        } else {
            button.classList.remove('visible');
        }
    });
}

// Update process details function
async function updateProcessDetails(pid) {
    try {
        const response = await fetch(`/api/process/${pid}`);
        const details = await response.json();
        
        console.log('Process details received:', details);
        
        // Only update if this is still the active process
        if (pid === activeProcessPid) {
            document.getElementById('modalTitle').textContent = `Process Details: ${details.name}`;
            document.getElementById('detailPid').textContent = `${details.pid} (${details.pidHex})`;
            const descriptionCell = document.querySelector('#detailDescription .text-content');
            console.log('Setting description:', details.description);
            descriptionCell.textContent = details.description || 'N/A';
            document.getElementById('detailStatus').textContent = details.status;
            document.getElementById('detailUsername').textContent = details.username;
            document.getElementById('detailCpu').textContent = `${details.cpuUsage.toFixed(1)}%`;
            document.getElementById('detailMemory').textContent = formatBytes(details.workingSetPrivate);
            
            const pathCell = document.querySelector('#detailPath .text-content');
            pathCell.textContent = details.imagePath;
            
            const cmdCell = document.querySelector('#detailCmd .text-content');
            cmdCell.textContent = details.commandLine;
            
            document.getElementById('detailArch').textContent = details.is64Bit ? '64-bit' : '32-bit';
            document.getElementById('detailProtection').textContent = details.isProtected ? 'Protected' : 'Not Protected';
            
            // Handle PE header row visibility and controls
            const peHeaderRow = document.getElementById('peHeaderRow');
            const memoryScanRow = document.getElementById('memoryScanRow');
            const antiTamperingRow = document.getElementById('antiTamperingRow');
            const threadMonitoringRow = document.getElementById('threadMonitoringRow');
            
            if (details.isProtected) {
                peHeaderRow.style.display = ''; // Show the row
                memoryScanRow.style.display = ''; // Show the row
                antiTamperingRow.style.display = ''; // Show the row
                threadMonitoringRow.style.display = ''; // Show the row
                updatePEHeaderStatus(pid); // Update PE header encryption status
                updateMemoryScanStatus(pid); // Update memory scan detection status
                updateAntiTamperingStatus(pid); // Update anti-tampering status
                updateThreadMonitoringStatus(pid); // Update thread monitoring status
            } else {
                peHeaderRow.style.display = 'none'; // Hide the row
                memoryScanRow.style.display = 'none'; // Hide the row
                antiTamperingRow.style.display = 'none'; // Hide the row
                threadMonitoringRow.style.display = 'none'; // Hide the row
            }
            
            // Check for truncated content
            checkTruncation();

            // Update suspend/resume button text based on process status
            const btnSuspendResume = document.getElementById('btnSuspendResume');
            const buttonText = btnSuspendResume.querySelector('span');
            const buttonIcon = btnSuspendResume.querySelector('i');
            
            if (details.status.toLowerCase().includes('suspended')) {
                buttonText.textContent = 'Resume Process';
                buttonIcon.textContent = 'play_arrow';
                btnSuspendResume.setAttribute('data-action', 'resume');
            } else {
                buttonText.textContent = 'Suspend Process';
                buttonIcon.textContent = 'pause';
                btnSuspendResume.setAttribute('data-action', 'suspend');
            }
        }
    } catch (error) {
        console.error('Error updating process details:', error);
    }
}

// Get PE header encryption status
async function updatePEHeaderStatus(pid) {
    try {
        const response = await fetch('/api/process/check_pe_headers', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        const data = await response.json();
        
        const statusElement = document.getElementById('peHeaderStatus');
        const encryptBtn = document.getElementById('btnEncryptPE');
        const decryptBtn = document.getElementById('btnDecryptPE');
        
        if (data.isEncrypted) {
            statusElement.textContent = 'Encrypted';
            statusElement.style.color = '#4caf50'; // Green
            encryptBtn.disabled = true;
            decryptBtn.disabled = false;
        } else {
            statusElement.textContent = 'Not Encrypted';
            statusElement.style.color = '#ff9800'; // Orange
            encryptBtn.disabled = false;
            decryptBtn.disabled = true;
        }
    } catch (error) {
        console.error('Error getting PE header status:', error);
        document.getElementById('peHeaderStatus').textContent = 'Status Unknown';
        document.getElementById('peHeaderStatus').style.color = '#f44336'; // Red
    }
}

// Get memory scan detection status
async function updateMemoryScanStatus(pid) {
    try {
        const response = await fetch('/api/process/check_memory_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        const data = await response.json();
        
        const statusElement = document.getElementById('memoryScanStatus');
        const enableBtn = document.getElementById('btnEnableMemoryScan');
        const disableBtn = document.getElementById('btnDisableMemoryScan');
        
        if (data.isEnabled) {
            statusElement.textContent = 'Enabled';
            statusElement.style.color = '#4caf50'; // Green
            enableBtn.disabled = true;
            disableBtn.disabled = false;
        } else {
            statusElement.textContent = 'Disabled';
            statusElement.style.color = '#ff9800'; // Orange
            enableBtn.disabled = false;
            disableBtn.disabled = true;
        }
    } catch (error) {
        console.error('Error getting memory scan status:', error);
        document.getElementById('memoryScanStatus').textContent = 'Status Unknown';
        document.getElementById('memoryScanStatus').style.color = '#f44336'; // Red
    }
}

// Get anti-tampering status
async function updateAntiTamperingStatus(pid) {
    try {
        const response = await fetch('/api/process/check_anti_tampering', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        const data = await response.json();
        
        const statusElement = document.getElementById('antiTamperingStatus');
        const enableBtn = document.getElementById('btnEnableAntiTampering');
        const disableBtn = document.getElementById('btnDisableAntiTampering');
        
        if (data.isEnabled) {
            statusElement.textContent = 'Enabled';
            statusElement.style.color = '#4caf50'; // Green
            enableBtn.disabled = true;
            disableBtn.disabled = false;
        } else {
            statusElement.textContent = 'Disabled';
            statusElement.style.color = '#ff9800'; // Orange
            enableBtn.disabled = false;
            disableBtn.disabled = true;
        }
    } catch (error) {
        console.error('Error getting anti-tampering status:', error);
        document.getElementById('antiTamperingStatus').textContent = 'Status Unknown';
        document.getElementById('antiTamperingStatus').style.color = '#f44336'; // Red
    }
}

// Get thread monitoring status
async function updateThreadMonitoringStatus(pid) {
    try {
        const response = await fetch('/api/process/check_thread_monitoring', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        const data = await response.json();
        
        const statusElement = document.getElementById('threadMonitoringStatus');
        const enableBtn = document.getElementById('btnEnableThreadMonitoring');
        const disableBtn = document.getElementById('btnDisableThreadMonitoring');
        
        if (data.isEnabled) {
            statusElement.textContent = 'Enabled';
            statusElement.style.color = '#4caf50'; // Green
            enableBtn.disabled = true;
            disableBtn.disabled = false;
        } else {
            statusElement.textContent = 'Disabled';
            statusElement.style.color = '#ff9800'; // Orange
            enableBtn.disabled = false;
            disableBtn.disabled = true;
        }
    } catch (error) {
        console.error('Error getting thread monitoring status:', error);
        document.getElementById('threadMonitoringStatus').textContent = 'Status Unknown';
        document.getElementById('threadMonitoringStatus').style.color = '#f44336'; // Red
    }
}

// Handle PE header encryption
async function encryptPEHeaders(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/encrypt_pe_headers', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`PE Headers encrypted successfully for ${processInfo}`, 'success');
            updatePEHeaderStatus(pid);
        } else {
            showNotification(`Failed to encrypt PE Headers for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error encrypting PE headers:', error);
        showNotification(`Error encrypting PE Headers for process (PID: ${pid})`, 'error');
    }
}

// Handle PE header decryption
async function decryptPEHeaders(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/decrypt_pe_headers', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`PE Headers decrypted successfully for ${processInfo}`, 'success');
            updatePEHeaderStatus(pid);
        } else {
            showNotification(`Failed to decrypt PE Headers for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error decrypting PE headers:', error);
        showNotification(`Error decrypting PE Headers for process (PID: ${pid})`, 'error');
    }
}

// Enable memory scan detection
async function enableMemoryScan(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/enable_memory_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`Memory scan detection enabled successfully for ${processInfo}`, 'success');
            updateMemoryScanStatus(pid);
        } else {
            showNotification(`Failed to enable memory scan detection for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error enabling memory scan detection:', error);
        showNotification(`Error enabling memory scan detection for process (PID: ${pid})`, 'error');
    }
}

// Disable memory scan detection
async function disableMemoryScan(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/disable_memory_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`Memory scan detection disabled successfully for ${processInfo}`, 'success');
            updateMemoryScanStatus(pid);
        } else {
            showNotification(`Failed to disable memory scan detection for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error disabling memory scan detection:', error);
        showNotification(`Error disabling memory scan detection for process (PID: ${pid})`, 'error');
    }
}

// Enable anti-tampering
async function enableAntiTampering(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/enable_anti_tampering', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`Anti-tampering protection enabled successfully for ${processInfo}`, 'success');
            updateAntiTamperingStatus(pid);
        } else {
            showNotification(`Failed to enable anti-tampering protection for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error enabling anti-tampering:', error);
        showNotification(`Error enabling anti-tampering protection for process (PID: ${pid})`, 'error');
    }
}

// Disable anti-tampering
async function disableAntiTampering(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/disable_anti_tampering', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`Anti-tampering protection disabled successfully for ${processInfo}`, 'success');
            updateAntiTamperingStatus(pid);
        } else {
            showNotification(`Failed to disable anti-tampering protection for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error disabling anti-tampering:', error);
        showNotification(`Error disabling anti-tampering protection for process (PID: ${pid})`, 'error');
    }
}

// Enable thread monitoring
async function enableThreadMonitoring(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/enable_thread_monitoring', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`Thread monitoring enabled successfully for ${processInfo}`, 'success');
            updateThreadMonitoringStatus(pid);
        } else {
            showNotification(`Failed to enable thread monitoring for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error enabling thread monitoring:', error);
        showNotification(`Error enabling thread monitoring for process (PID: ${pid})`, 'error');
    }
}

// Disable thread monitoring
async function disableThreadMonitoring(pid) {
    try {
        showLoading();
        
        // Get process details for the notification
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        const response = await fetch('/api/process/disable_thread_monitoring', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.success) {
            showNotification(`Thread monitoring disabled successfully for ${processInfo}`, 'success');
            updateThreadMonitoringStatus(pid);
        } else {
            showNotification(`Failed to disable thread monitoring for ${processInfo}: ${result.error}`, 'error');
        }
    } catch (error) {
        hideLoading();
        console.error('Error disabling thread monitoring:', error);
        showNotification(`Error disabling thread monitoring for process (PID: ${pid})`, 'error');
    }
}

// Initialize process controls
function initializeProcessControls(pid) {
    const btnTerminate = document.getElementById('btnTerminate');
    const btnSuspendResume = document.getElementById('btnSuspendResume');
    const btnViewModules = document.getElementById('btnViewModules');
    const btnEncryptPE = document.getElementById('btnEncryptPE');
    const btnDecryptPE = document.getElementById('btnDecryptPE');
    const btnEnableMemoryScan = document.getElementById('btnEnableMemoryScan');
    const btnDisableMemoryScan = document.getElementById('btnDisableMemoryScan');
    const btnEnableAntiTampering = document.getElementById('btnEnableAntiTampering');
    const btnDisableAntiTampering = document.getElementById('btnDisableAntiTampering');
    const btnEnableThreadMonitoring = document.getElementById('btnEnableThreadMonitoring');
    const btnDisableThreadMonitoring = document.getElementById('btnDisableThreadMonitoring');
    
    btnTerminate.onclick = function() {
        terminateProcess(pid);
    };
    
    btnSuspendResume.onclick = function() {
        const action = btnSuspendResume.getAttribute('data-action');
        toggleProcessSuspension(pid, action === 'resume');
    };
    
    btnViewModules.onclick = function() {
        showModules(pid);
    };
    
    btnEncryptPE.onclick = function() {
        encryptPEHeaders(pid);
    };
    
    btnDecryptPE.onclick = function() {
        decryptPEHeaders(pid);
    };
    
    btnEnableMemoryScan.onclick = function() {
        enableMemoryScan(pid);
    };
    
    btnDisableMemoryScan.onclick = function() {
        disableMemoryScan(pid);
    };
    
    btnEnableAntiTampering.onclick = function() {
        enableAntiTampering(pid);
    };
    
    btnDisableAntiTampering.onclick = function() {
        disableAntiTampering(pid);
    };
    
    btnEnableThreadMonitoring.onclick = function() {
        enableThreadMonitoring(pid);
    };
    
    btnDisableThreadMonitoring.onclick = function() {
        disableThreadMonitoring(pid);
    };
}

// Add resize observer to handle window resizing
const resizeObserver = new ResizeObserver(() => {
    checkTruncation();
});

// Global function to show process details
async function showProcessDetails(pid) {
    activeProcessPid = pid;
    modal.style.display = "block";
    
    // Start observing the modal content for resize events
    resizeObserver.observe(modal.querySelector('.modal-content'));
    
    await updateProcessDetails(pid);
    initializeProcessControls(pid);
    
    // Clear any existing interval
    if (processDetailsInterval) {
        clearInterval(processDetailsInterval);
    }
    
    // Start updating process details every second
    processDetailsInterval = setInterval(() => {
        if (modal.style.display === "none") {
            clearInterval(processDetailsInterval);
            processDetailsInterval = null;
            activeProcessPid = null;
            resizeObserver.disconnect();
        } else {
            updateProcessDetails(pid);
        }
    }, 1000);
}

// Add modal to document
document.body.insertAdjacentHTML('beforeend', modalHtml);

// Initialize modal elements
const modal = document.getElementById("processDetailsModal");
const span = modal.querySelector(".close");

// Modal close button handler
span.onclick = function() {
    modal.style.display = "none";
    if (processDetailsInterval) {
        clearInterval(processDetailsInterval);
        processDetailsInterval = null;
        activeProcessPid = null;
    }
}

// Click outside modal to close
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
        if (processDetailsInterval) {
            clearInterval(processDetailsInterval);
            processDetailsInterval = null;
            activeProcessPid = null;
        }
    }
}

let activeProcessPid = null;
let processDetailsInterval = null;

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add styles to document
const styleSheet = document.createElement("style");
styleSheet.textContent = modalStyles;
document.head.appendChild(styleSheet);

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Load system info
    fetch('/api/system-info')
        .then(response => response.json())
        .then(data => {
            document.getElementById('osVersion').textContent = data.osVersion;
            document.getElementById('computerName').textContent = data.computerName;
            document.getElementById('username').textContent = data.username;
        });

    // Setup search input with optimized handler
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    const handleSearch = debounce((value) => {
        lastSearchQuery = value.trim();
        searchRegex = createSearchRegex(lastSearchQuery);
        applySearchAndSort();
        // Show/hide clear button based on input value
        searchClear.style.display = value.length > 0 ? 'flex' : 'none';
    }, 150);

    searchInput.addEventListener('input', (e) => handleSearch(e.target.value));
    
    // Clear button handler
    searchClear.addEventListener('click', () => {
        searchInput.value = '';
        handleSearch('');
        searchInput.focus();
    });

    // Initialize clear button visibility
    searchClear.style.display = 'none';

    // Filter change handlers
    document.getElementById('archFilter').addEventListener('change', (e) => {
        archFilter = e.target.value;
        applySearchAndSort();
    });

    document.getElementById('protectionFilter').addEventListener('change', (e) => {
        protectionFilter = e.target.value;
        applySearchAndSort();
    });

    document.getElementById('systemFilter').addEventListener('change', (e) => {
        systemFilter = e.target.value;
        applySearchAndSort();
    });

    document.getElementById('windowFilter').addEventListener('change', (e) => {
        windowFilter = e.target.value;
        applySearchAndSort();
    });

    // Setup sorting
    document.querySelectorAll('th[data-column]').forEach(th => {
        th.addEventListener('click', () => {
            if (th.dataset.column) {
                sortProcesses(th.dataset.column);
            }
        });
    });

    // Initialize sort indicators
    const nameHeader = document.querySelector('th[data-column="name"]');
    if (nameHeader) {
        nameHeader.classList.add('sorted');
    }
    currentSortColumn = 'name';
    sortDirection = 1;

    // Setup auto-refresh
    const autoRefreshCheckbox = document.getElementById('autoRefresh');
    const refreshIntervalSelect = document.getElementById('refreshInterval');

    function updateAutoRefresh() {
        if (refreshIntervalId) {
            clearInterval(refreshIntervalId);
            refreshIntervalId = null;
        }
        
        if (autoRefreshCheckbox.checked) {
            const interval = parseInt(refreshIntervalSelect.value);
            if (interval > 0) {
                refreshIntervalId = setInterval(updateProcessList, interval);
            }
        }
    }

    autoRefreshCheckbox.addEventListener('change', updateAutoRefresh);
    refreshIntervalSelect.addEventListener('change', updateAutoRefresh);

    // Initial load and start auto-refresh
    updateProcessList();
    if (autoRefreshCheckbox.checked) {
        const interval = parseInt(refreshIntervalSelect.value);
        if (interval > 0) {
            refreshIntervalId = setInterval(updateProcessList, interval);
        }
    }
});

async function terminateProcess(pid) {
    try {
        // Get process details for the confirmation dialog
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        if (confirm(`Are you sure you want to terminate process ${processInfo}?`)) {
            const response = await fetch('/api/process/terminate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ pid })
            });
            
            const result = await response.json();
            if (result.success) {
                showNotification(`Successfully terminated process ${processInfo}`, 'success');
                modal.style.display = "none";
            } else {
                showNotification(`Failed to terminate process ${processInfo}: ${result.error}`, 'error');
            }
        }
    } catch (error) {
        console.error('Error terminating process:', error);
        showNotification(`Failed to terminate process (PID: ${pid})`, 'error');
    }
}

async function toggleProcessSuspension(pid, isSuspended) {
    const action = isSuspended ? 'resume' : 'suspend';
    try {
        const response = await fetch(`/api/process/${action}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pid })
        });
        
        const result = await response.json();
        if (result.success) {
            // Get process details for the notification
            const details = await fetch(`/api/process/${pid}`).then(r => r.json());
            const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
            
            showNotification(
                `Successfully ${action === 'suspend' ? 'suspended' : 'resumed'} process ${processInfo}`,
                'success'
            );
            await updateProcessDetails(pid);
            setTimeout(async () => {
                await updateProcessDetails(pid);
            }, 500);
        } else {
            const details = await fetch(`/api/process/${pid}`).then(r => r.json());
            const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
            showNotification(
                `Failed to ${action === 'suspend' ? 'suspend' : 'resume'} process ${processInfo}: ${result.error}`,
                'error'
            );
        }
    } catch (error) {
        console.error(`Error ${action}ing process:`, error);
        showNotification(`Failed to ${action === 'suspend' ? 'suspend' : 'resume'} process (PID: ${pid})`, 'error');
    }
}

async function showModules(pid) {
    const modulesModal = document.getElementById('modulesModal');
    const modulesList = document.getElementById('modulesList');
    modulesModal.style.display = "block";
    
    // Prevent scroll propagation
    const modulesListDiv = modulesModal.querySelector('.modules-list');
    modulesListDiv.addEventListener('wheel', (e) => {
        const maxScroll = modulesListDiv.scrollHeight - modulesListDiv.clientHeight;
        const currentScroll = modulesListDiv.scrollTop;
        
        // Only prevent default if we're not at the top/bottom or scrolling in the available direction
        if ((currentScroll > 0 && currentScroll < maxScroll) || 
            (currentScroll === 0 && e.deltaY > 0) || 
            (currentScroll === maxScroll && e.deltaY < 0)) {
            e.stopPropagation();
            e.preventDefault();
            modulesListDiv.scrollTop += e.deltaY;
        }
    }, { passive: false });

    // Get process details for the title
    const processDetails = await fetch(`/api/process/${pid}`).then(r => r.json());
    document.getElementById('modulesTitle').textContent = 
        `Modules - ${processDetails.name} (PID: ${processDetails.pid} / ${processDetails.pidHex})`;
    
    // Initialize dragging
    const modalContent = modulesModal.querySelector('.modal-content');
    const modalHeader = modalContent.querySelector('.modal-header');
    
    let isDragging = false;
    let currentX;
    let currentY;
    let initialX;
    let initialY;
    let xOffset = 0;
    let yOffset = 0;
    
    modalHeader.addEventListener('mousedown', dragStart);
    document.addEventListener('mousemove', drag);
    document.addEventListener('mouseup', dragEnd);
    
    function dragStart(e) {
        const rect = modalContent.getBoundingClientRect();
        initialX = e.clientX - rect.left;
        initialY = e.clientY - rect.top;
        if (e.target === modalHeader) {
            isDragging = true;
        }
    }
    
    function drag(e) {
        if (isDragging) {
            e.preventDefault();
            const x = e.clientX - initialX;
            const y = e.clientY - initialY;
            modalContent.style.left = `${x}px`;
            modalContent.style.top = `${y}px`;
        }
    }
    
    function dragEnd(e) {
        isDragging = false;
    }
    
    try {
        const response = await fetch(`/api/process/${pid}/modules`);
        const modules = await response.json();
        
        // Add sorting functionality
        const modulesTable = modulesModal.querySelector('table');
        modulesTable.querySelectorAll('th').forEach(th => {
            if (th.dataset.sort) {
                th.addEventListener('click', () => {
                    const column = th.dataset.sort;
                    let isAsc = th.classList.contains('sorted');
                    isAsc = th.classList.contains('reverse') ? true : !isAsc;
                    
                    // Remove sorted class from all headers
                    modulesTable.querySelectorAll('th').forEach(header => {
                        header.classList.remove('sorted', 'reverse');
                    });
                    
                    // Sort modules
                    modules.sort((a, b) => {
                        let valueA = a[column];
                        let valueB = b[column];
                        
                        if (column === 'size') {
                            return isAsc ? valueB - valueA : valueA - valueB;
                        }
                        if (column === 'baseAddress') {
                            valueA = parseInt(valueA, 16);
                            valueB = parseInt(valueB, 16);
                            return isAsc ? valueB - valueA : valueA - valueB;
                        }
                        return isAsc ? 
                            valueA.localeCompare(valueB) : 
                            valueB.localeCompare(valueA);
                    });
                    
                    th.classList.add('sorted');
                    if (!isAsc) th.classList.add('reverse');
                    
                    // Update table
                    updateModulesList(modules);
                });
            }
        });
        
        updateModulesList(modules);
        
        function updateModulesList(modules) {
            modulesList.innerHTML = modules.map(module => `
                <tr>
                    <td class="expandable-cell">
                        <div class="text-content">${module.name}</div>
                        <button class="expand-btn" onclick="toggleExpand(this)">Show More</button>
                    </td>
                    <td>${module.baseAddress}</td>
                    <td>${formatBytes(module.size)}</td>
                    <td class="expandable-cell">
                        <div class="text-content">${module.description || 'N/A'}</div>
                        <button class="expand-btn" onclick="toggleExpand(this)">Show More</button>
                    </td>
                    <td class="expandable-cell">
                        <div class="text-content">${module.path}</div>
                        <button class="expand-btn" onclick="toggleExpand(this)">Show More</button>
                    </td>
                </tr>
            `).join('');
            checkTruncation();
        }
    } catch (error) {
        console.error('Error fetching modules:', error);
        showNotification('Failed to fetch process modules', 'error');
    }
}

// Add close handler for modules modal
document.querySelector('#modulesModal .close').onclick = function() {
    document.getElementById('modulesModal').style.display = "none";
};

async function unprotectProcess(pid) {
    try {
        const details = await fetch(`/api/process/${pid}`).then(r => r.json());
        const processInfo = `${details.name} (PID: ${details.pid} / ${details.pidHex})`;
        
        if (confirm(`Are you sure you want to remove protection from process ${processInfo}?`)) {
            const response = await fetch('/api/unprotect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ pid })
            });
            
            const result = await response.json();
            if (result.success) {
                showNotification(`Successfully removed protection from process ${processInfo}`, 'success');
                updateProcessList();
            } else {
                showNotification(`Failed to remove protection from process ${processInfo}: ${result.error}`, 'error');
            }
        }
    } catch (error) {
        console.error('Error unprotecting process:', error);
        showNotification(`Failed to remove protection from process (PID: ${pid})`, 'error');
    }
}
