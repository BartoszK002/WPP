let processes = [];
let filteredProcesses = [];
let lastSearchQuery = '';
let refreshIntervalId = null;
let currentSortColumn = 'name';
let sortDirection = 1;
let archFilter = 'all';
let protectionFilter = 'all';

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
    // Only show loading on initial load
    if (isInitialLoad) {
        showLoading();
    }
    
    fetch('/api/processes')
        .then(response => response.json())
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
            if (isInitialLoad) {
                hideLoading();
                isInitialLoad = false;
            }
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

    if (archFilter !== 'all') {
        filteredProcesses = filteredProcesses.filter(process => {
            return (archFilter === 'x64') === process.is64Bit;
        });
    }

    if (protectionFilter !== 'all') {
        filteredProcesses = filteredProcesses.filter(process => {
            return (protectionFilter === 'protected') === process.isProtected;
        });
    }

    // Apply sorting
    const compareFn = getComparisonFunction(currentSortColumn);
    filteredProcesses.sort(compareFn);

    // Prepare all row content first
    const rowsHTML = filteredProcesses.map(process => {
        const iconHtml = process.icon ? 
            `<div class="process-icon"><img src="data:image/png;base64,${process.icon}" alt="" onerror="this.style.display='none'"></div>` :
            `<div class="process-icon"></div>`;
        
        const statusIcon = process.isProtected ? 
            '<span class="status-icon status-protected"><i class="material-icons">security</i>Protected</span>' :
            '<span class="status-icon status-unprotected"><i class="material-icons">lock_open</i>Unprotected</span>';

        const archClass = process.is64Bit ? 'arch-x64' : 'arch-x86';
        const archIcon = `<span class="arch-icon ${archClass}"><i class="material-icons">memory</i>${process.is64Bit ? 'x64' : 'x86'}</span>`;
        
        return `<tr data-pid="${process.pid}">
            <td title="${process.name}">
                ${iconHtml}
                ${process.name}
            </td>
            <td title="PID: ${process.pid}">${process.pid} (0x${process.pid.toString(16).toUpperCase()})</td>
            <td>${archIcon}</td>
            <td>${statusIcon}</td>
            <td>
                ${!process.isProtected ? `<button onclick="protectProcess(${process.pid})">Protect</button>` : ''}
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

function protectProcess(pid) {
    const process = processes.find(p => p.pid === pid);
    if (!process) return;

    fetch('/api/protect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ pid: pid })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            process.isProtected = true;
            showNotification(`Process "${process.name}" (PID: ${pid}) protected successfully`);
            applySearchAndSort();
        } else {
            showNotification(data.error || 'Failed to protect process', 'error');
        }
    })
    .catch(error => {
        showNotification('Error protecting process: ' + error, 'error');
    });
}

function showNotification(message, type = 'success') {
    // Remove any existing notification
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        ${message}
        <span class="close-btn" onclick="this.parentElement.remove()">✕</span>
    `;
    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
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
    const overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.innerHTML = '<div class="loading-spinner"></div>';
    document.body.appendChild(overlay);
}

function hideLoading() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

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
    const handleSearch = debounce((value) => {
        lastSearchQuery = value.trim();
        searchRegex = createSearchRegex(lastSearchQuery);
        applySearchAndSort();
    }, 150);

    searchInput.addEventListener('input', (e) => handleSearch(e.target.value));

    // Filter change handlers
    document.getElementById('archFilter').addEventListener('change', (e) => {
        archFilter = e.target.value;
        applySearchAndSort();
    });

    document.getElementById('protectionFilter').addEventListener('change', (e) => {
        protectionFilter = e.target.value;
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

    // Initial load
    updateProcessList();
    updateAutoRefresh();
});
