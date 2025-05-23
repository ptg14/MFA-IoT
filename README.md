ptg14: update readme

GitHub Copilot: # WeatherWeb

A secure web application for managing and displaying weather data from IoT devices.

## Features

- **User Authentication**: Secure login system with password and two-factor authentication (pass matrix)
- **IoT Device Management**: Registration, authentication and monitoring of IoT weather devices
- **Weather Dashboard**: Real-time display of temperature, humidity and weather conditions
- **Security**: Challenge-response device authentication with RSA encryption
- **Status Monitoring**: Track device status (Verified, Suspicious, Invalid)
- **Location Display**: Shows device locations based on GPS coordinates
- **Automatic Refresh**: Configurable auto-refresh for weather data

## Technology Stack

- **Backend**: Node.js with [Express](https://expressjs.com/)
- **Database**: [SQLite3](https://www.sqlite.org/index.html)
- **Frontend**: HTML, CSS, JavaScript
- **Security**: RSA encryption, session management
- **Protocols**: HTTPS for secure communication

## Installation

### Prerequisites

- Node.js (v12 or higher)
- npm

### Setup

1. Clone the repository
   ```bash
   git clone https://github.com/ptg14/MFA-IoT.git
   cd WeatherWeb
   ```

2. Install dependencies
   ```bash
   npm install
   ```

3. Create SSL certificates
   ```bash
   mkdir -p ssl
   openssl req -nodes -new -x509 -keyout ssl/server.key -out ssl/server.cert
   ```

4. Start the server
   ```bash
   npm start
   ```

5. Access the application
   ```
   https://localhost:3443
   ```

## IoT Device Simulator

The project includes a Python simulator (test.py) for testing IoT device integration:

1. Install Python requirements
   ```bash
   pip install requests cryptography
   ```

2. Run the simulator
   ```bash
   python test.py -s https://localhost:3443 -i 30 -l 1
   ```

   Options:
   - `-s`: Server URL
   - `-i`: Data transmission interval in seconds
   - `-l`: Log level (0=None, 1=notifications only, 2=all)
   - `-d`: Custom device ID
   - `--no-verify-ssl`: Disable SSL verification for self-signed certificates
   - `--save-profile`: Save device profile to a file
   - `--load-profile`: Load device profile from a file

## Project Structure

```
├── database/          # SQLite database files
├── public/            # Static files
│   ├── css/           # Stylesheets
│   └── js/            # Client-side JavaScript
├── src/               # Source code
│   ├── app.js         # Main application entry point
│   ├── controllers/   # Business logic
│   ├── middleware/    # Request processing middleware
│   ├── routes/        # API routes
│   ├── utils/         # Utility functions
│   └── views/         # HTML templates
├── ssl/               # SSL certificates
├── test.py            # IoT device simulator
└── package.json       # Project dependencies
```

## API Endpoints

### Authentication
- `POST /api/auth/register`: Register a new user
- `POST /api/auth/login`: Login with username/password
- `POST /api/auth/setPassMatrix`: Set up pass matrix
- `POST /api/auth/verifyPassMatrix`: Verify pass matrix entries
- `GET /api/auth/logout`: User logout

### IoT Devices
- `POST /iot/register`: Register a new IoT device
- `POST /iot/login`: Authenticate an IoT device
- `POST /iot/challenge`: Complete challenge-response authentication
- `POST /iot/weather`: Submit weather data from a device

### Weather Data
- `GET /api/weather`: Get all weather data

## Security Features

- **Challenge-Response Authentication**: Devices must prove identity via RSA encryption
- **Two-Factor Authentication**: Users authenticate with password + pass matrix
- **Device Fingerprinting**: Hardware identifiers (dmidecode hash, lscpu hash) verify device identity
- **Suspicious Activity Detection**: Changes in device MAC address or GPS location flag devices
- **HTTPS Protocol**: All communication encrypted via SSL

## Pass Matrix Authentication

The system implements a unique pass matrix authentication as a second factor:

1. During registration, users set a pass matrix string
2. During login, users are presented with 4x4 matrices of characters
3. Users must select the correct characters from each matrix that match their pass matrix
4. This provides protection against keyloggers and phishing attacks

## Automatic Dashboard Updates

The dashboard features:

- Real-time weather data display
- Configurable auto-refresh settings
- Status indicators for device health
- Location information based on GPS coordinates

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE.txt file for details.