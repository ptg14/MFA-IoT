document.addEventListener('DOMContentLoaded', async function () {
    // Check if we're on the dashboard page
    const devicesContainer = document.getElementById('devices-container');
    if (devicesContainer) {
        loadDevicesData();

        setupAutoRefresh();
    }

    // Handle login form if present
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Handle register form if present
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    setupPasswordToggles();
});

function setupPasswordToggles() {
    const toggleButtons = document.querySelectorAll('.password-toggle');

    toggleButtons.forEach(button => {
        button.addEventListener('click', function () {
            const container = this.closest('.password-container');
            const passwordInput = container.querySelector('input');

            // Toggle the input type
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.querySelector('i').classList.remove('fa-eye');
                this.querySelector('i').classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                this.querySelector('i').classList.remove('fa-eye-slash');
                this.querySelector('i').classList.add('fa-eye');
            }
        });
    });
}

// Auto-refresh configuration
const REFRESH_INTERVAL = 30000; // 30 seconds
let refreshTimer = null;
let isAutoRefreshEnabled = true;

function setupAutoRefresh() {
    // Add refresh controls to the page
    const refreshControls = document.createElement('div');
    refreshControls.className = 'refresh-controls';
    refreshControls.innerHTML = `
        <div class="auto-refresh-status">
            <span id="refresh-status-indicator" class="status-active">●</span>
            <span>Auto-refresh: </span>
            <span id="refresh-status-text">Active</span>
            <button id="toggle-refresh" class="btn btn-sm btn-primary">Pause</button>
        </div>
        <div class="last-updated">
            Last refresh: <span id="last-refresh-time">${new Date().toLocaleTimeString()}</span>
        </div>
    `;

    // Try multiple potential containers in order of preference
    const deviceContainer = document.getElementById('devices-container');
    const dashboardHeader = document.querySelector('.dashboard-header');
    const mainContent = document.querySelector('.main-content');
    const container = document.querySelector('.container');

    // Find a suitable container or create one
    let targetElement = dashboardHeader || mainContent || container || deviceContainer;

    if (!targetElement && deviceContainer) {
        // If no container found, but devices container exists,
        // create a header element before the devices container
        const newHeader = document.createElement('div');
        newHeader.className = 'dashboard-header';
        newHeader.innerHTML = '<h2>Dashboard</h2>';

        deviceContainer.parentNode.insertBefore(newHeader, deviceContainer);
        targetElement = newHeader;
    }

    if (targetElement) {
        // Decide where to insert the controls
        if (targetElement === deviceContainer) {
            // Insert before the devices container
            targetElement.insertAdjacentElement('beforebegin', refreshControls);
        } else {
            // Insert after other container types
            targetElement.insertAdjacentElement('afterend', refreshControls);
        }

        // Set up the toggle button - ONLY after we've added the controls to the DOM
        const toggleButton = document.getElementById('toggle-refresh');
        if (toggleButton) {
            toggleButton.addEventListener('click', toggleAutoRefresh);
        }

        // Start the auto-refresh timer
        startRefreshTimer();
    } else {
        console.warn('Could not find or create a suitable container for auto-refresh controls.');
        return; // Exit function if we can't add the controls
    }
}

function startRefreshTimer() {
    // Clear any existing timer
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }

    // Set new timer if auto-refresh is enabled
    if (isAutoRefreshEnabled) {
        refreshTimer = setInterval(() => {
            loadDevicesData();
            document.getElementById('last-refresh-time').textContent = new Date().toLocaleTimeString();
        }, REFRESH_INTERVAL);
    }
}

function toggleAutoRefresh() {
    isAutoRefreshEnabled = !isAutoRefreshEnabled;

    // Update UI elements
    const indicator = document.getElementById('refresh-status-indicator');
    const statusText = document.getElementById('refresh-status-text');
    const toggleButton = document.getElementById('toggle-refresh');

    if (isAutoRefreshEnabled) {
        indicator.className = 'status-active';
        statusText.textContent = 'Active';
        toggleButton.textContent = 'Pause';
        startRefreshTimer();
    } else {
        indicator.className = 'status-paused';
        statusText.textContent = 'Paused';
        toggleButton.textContent = 'Resume';
        clearInterval(refreshTimer);
    }
}

function loadDevicesData() {
    // Show loading indicator
    const container = document.getElementById('devices-container');
    if (container) {
        container.classList.add('loading');
    }

    fetch('/api/weather')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            displayDevicesData(data);
            // Removed updateMainWeatherDisplay call

            // Remove loading state
            if (container) {
                container.classList.remove('loading');
            }
        })
        .catch(error => {
            console.error('Error fetching weather data:', error);
            document.getElementById('devices-container').innerHTML =
                '<div class="error">Error loading devices. Please try again later.</div>';

            // Remove loading state
            if (container) {
                container.classList.remove('loading');
            }
        });
}

function displayDevicesData(devices) {
    const container = document.getElementById('devices-container');

    if (devices.length === 0) {
        container.innerHTML = '<div class="no-data">No IoT devices are reporting data</div>';
        return;
    }

    let html = '';
    devices.forEach(device => {
        const statusClass = `status-${device.status.toLowerCase()}`;
        const formattedTime = formatDateTime(device.update_time);
        const locationText = device.gps ? formatLocation(device.gps) : 'Unknown location';
        const statusIcon = getStatusIcon(device.status);

        html += `
            <div class="device-card">
                <div class="device-header">
                    <div class="device-name">
                        ${device.device} (${device.type || 'Unknown'})
                    </div>
                    <div class="status-indicator ${statusClass}">
                        ${statusIcon} ${device.status}
                    </div>
                </div>
                <div class="weather-info">
                    <i class="fas fa-temperature-high"></i> Temperature: ${device.temperature || '--'}°C
                    <i class="fas fa-droplet"></i> Humidity: ${device.humidity || '--'}%
                    <i class="fas fa-cloud"></i> Condition: ${device.weather || '--'}
                </div>
                <div class="device-footer">
                    <div class="update-time">Last updated: ${formattedTime}</div>
                    <div class="location-info">${locationText}</div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// Add this new helper function to format GPS data into readable location
function formatLocation(gpsString) {
    if (!gpsString) return 'Unknown';

    try {
        // GPS format might be "latitude,longitude"
        const [latitude, longitude] = gpsString.split(',').map(coord => parseFloat(coord.trim()));

        // Return formatted as location-like name
        if (!isNaN(latitude) && !isNaN(longitude)) {
            // Check if coordinates are within Vietnam's boundaries
            if (latitude >= 8.5 && latitude <= 23.5 && longitude >= 102.0 && longitude <= 109.5) {
                // Determine region in Vietnam (simplified approach)
                let region = '';

                // North Vietnam
                if (latitude > 20) {
                    region = 'Northern Vietnam';
                    // Specific locations in northern Vietnam
                    if (longitude > 105.7 && longitude < 106.0 && latitude > 20.8 && latitude < 21.2) {
                        region = 'Hanoi area';
                    } else if (longitude > 106.5 && longitude < 107.1 && latitude > 20.7 && latitude < 21.2) {
                        region = 'Halong Bay area';
                    }
                }
                // Central Vietnam
                else if (latitude > 13 && latitude <= 20) {
                    region = 'Central Vietnam';
                    // Specific locations in central Vietnam
                    if (longitude > 107.8 && longitude < 108.4 && latitude > 15.8 && latitude < 16.2) {
                        region = 'Da Nang area';
                    } else if (longitude > 107.4 && longitude < 107.7 && latitude > 16.3 && latitude < 16.6) {
                        region = 'Hue area';
                    }
                }
                // Southern Vietnam
                else {
                    region = 'Southern Vietnam';
                    // Specific locations in southern Vietnam
                    if (longitude > 106.5 && longitude < 107.0 && latitude > 10.7 && latitude < 11.0) {
                        region = 'Ho Chi Minh City area';
                    } else if (longitude > 105.0 && longitude < 105.8 && latitude > 10.0 && latitude < 10.5) {
                        region = 'Mekong Delta';
                    }
                }

                return `${region} (${latitude.toFixed(3)},${longitude.toFixed(3)})`;
            } else {
                // Fallback for non-Vietnam coordinates (keeping original functionality)
                let direction = '';
                if (latitude > 0) {
                    direction += 'North';
                } else {
                    direction += 'South';
                }

                direction += ' ';

                if (longitude > 0) {
                    direction += 'East';
                } else {
                    direction += 'West';
                }

                return `Location ${direction} (${Math.abs(latitude).toFixed(3)},${Math.abs(longitude).toFixed(3)})`;
            }
        }
        return gpsString; // Return original if parsing fails
    } catch (error) {
        console.error('Error formatting GPS data:', error);
        return gpsString;
    }
}

function getStatusIcon(status) {
    switch (status.toLowerCase()) {
        case 'verified':
            return '<i class="fas fa-check-circle"></i>';
        case 'suspicious':
            return '<i class="fas fa-exclamation-triangle"></i>';
        case 'invalid':
            return '<i class="fas fa-times-circle"></i>';
        default:
            return '<i class="fas fa-question-circle"></i>';
    }
}

function formatDateTime(dateTimeStr) {
    if (!dateTimeStr) return 'Unknown';

    const date = new Date(dateTimeStr);
    if (isNaN(date.getTime())) return dateTimeStr;

    return date.toLocaleString();
}

function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Show pass matrix form
                if (data.needPassMatrix) {
                    registerPassMatrix(username);
                } else if (data.requirePassMatrix) {
                    loginPassMatrix(username, data);
                } else {
                    alert(data.message);
                }
            } else {
                alert(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during login.');
        });
}

function handleRegister(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/api/auth/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Show set pass matrix form
                registerPassMatrix(username);
            } else {
                alert(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during registration.');
        });
}

function registerPassMatrix(username) {
    const container = document.querySelector('.container');
    const existingForm = container.querySelector('.weather-card');

    if (existingForm) {
        existingForm.innerHTML = `
            <h2><i class="fas fa-key"></i> Set Pass Matrix</h2>
            <p>Please set your pass matrix for additional security.</p>

            <form id="setPassMatrixForm">
                <div class="form-group">
                    <label for="passMatrix"><i class="fas fa-table"></i> Pass Matrix:</label>
                    <div class="password-container">
                        <input type="password" id="passMatrix" name="passMatrix" required>
                        <button type="button" class="password-toggle" aria-label="Toggle password visibility">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <small>Your pass matrix is a secondary secret code (can be numbers, letters or symbols).</small>
                </div>
                <input type="hidden" id="username" value="${username}">
                <button type="submit"><i class="fas fa-save"></i> Save Pass Matrix</button>
            </form>
        `;

        // Add event listener to the new form
        document.getElementById('setPassMatrixForm').addEventListener('submit', function (e) {
            e.preventDefault();

            const passMatrix = document.getElementById('passMatrix').value;
            const username = document.getElementById('username').value;

            fetch('/api/auth/setPassMatrix', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, passMatrix })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Pass matrix set successfully! Please login.');
                        window.location.href = '/login';
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while setting pass matrix.');
                });
        });

        setupPasswordToggles();
    }
}

function loginPassMatrix(username, passMatrixData) {
    const container = document.querySelector('.container');
    const existingForm = container.querySelector('.weather-card');

    if (existingForm) {
        const passMatrixLength = passMatrixData.passMatrixLength;
        const passMatrixString = passMatrixData.passMatrix;

        // Create matrices HTML
        let matricesHTML = '';
        for (let matrixIndex = 0; matrixIndex < passMatrixLength; matrixIndex++) {
            const startIndex = matrixIndex * 16;
            const matrixChars = passMatrixString.slice(startIndex, startIndex + 16);

            matricesHTML += `
                <div class="matrix-container" data-matrix="${matrixIndex}">
                    <h4>Matrix ${matrixIndex + 1}</h4>
                    <div class="matrix-grid">
            `;

            for (let i = 0; i < 16; i++) {
                matricesHTML += `
                    <button type="button" class="matrix-cell" data-matrix="${matrixIndex}" data-char="${matrixChars[i]}">
                        ${matrixChars[i]}
                    </button>
                `;
            }

            matricesHTML += `
                    </div>
                    <div class="selected-char">Selected: <span id="selected-${matrixIndex}">None</span></div>
                </div>
            `;
        }

        existingForm.innerHTML = `
            <h2><i class="fas fa-key"></i> Enter Pass Matrix</h2>
            <p>Select one character from each 4x4 matrix below in order:</p>

            <form id="passMatrixForm">
                <div class="matrices-container">
                    ${matricesHTML}
                </div>
                <input type="hidden" id="username" value="${username}">
                <input type="hidden" id="selectedChars" value="">
                <button type="submit" id="verifyButton" disabled><i class="fas fa-check-circle"></i> Verify</button>
            </form>
        `;

        // Track selected characters
        const selectedChars = new Array(passMatrixLength).fill(null);

        // Add click handlers for matrix cells
        document.querySelectorAll('.matrix-cell').forEach(cell => {
            cell.addEventListener('click', function () {
                const matrixIndex = parseInt(this.dataset.matrix);
                const selectedChar = this.dataset.char;

                // Remove previous selection in this matrix
                document.querySelectorAll(`[data-matrix="${matrixIndex}"]`).forEach(c => {
                    c.classList.remove('selected');
                });

                // Add selection to clicked cell
                this.classList.add('selected');

                // Update selected character
                selectedChars[matrixIndex] = selectedChar;
                document.getElementById(`selected-${matrixIndex}`).textContent = selectedChar;

                // Update hidden input
                document.getElementById('selectedChars').value = selectedChars.join('');

                // Enable verify button if all matrices have selections
                const allSelected = selectedChars.every(char => char !== null);
                document.getElementById('verifyButton').disabled = !allSelected;
            });
        });

        // Add form submit handler
        document.getElementById('passMatrixForm').addEventListener('submit', function (e) {
            e.preventDefault();

            const selectedPassMatrix = document.getElementById('selectedChars').value;
            const username = document.getElementById('username').value;

            if (selectedPassMatrix.length !== passMatrixLength) {
                alert('Please select one character from each matrix.');
                return;
            }

            fetch('/api/auth/verifyPassMatrix', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, passMatrix: selectedPassMatrix })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Redirect to dashboard after successful verification
                        window.location.href = '/dashboard';
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred with pass matrix verification.');
                });
        });
    }
}
