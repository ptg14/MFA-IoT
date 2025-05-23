import requests
import json
import time
import random
import uuid
import hashlib
import base64
import os
import logging
import subprocess
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import urllib3

# Configure base logging with minimal formatting
logging.basicConfig(
    level=logging.INFO,  # Default to INFO level
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Create loggers with specific names
logger = logging.getLogger("IoTSimulator")
notification_logger = logging.getLogger("IoTSimulator.Notification")
request_logger = logging.getLogger("IoTSimulator.Request")
response_logger = logging.getLogger("IoTSimulator.Response")

# Set initial levels
notification_logger.setLevel(logging.INFO)
request_logger.setLevel(logging.WARNING)  # Initially disabled (higher than INFO)
response_logger.setLevel(logging.WARNING)  # Initially disabled (higher than INFO)


class WeatherIoTSimulator:
    def __init__(self, server_url, device_name=None, verify_ssl=True, cert_path=None):
        # Server configuration
        self.server_url = server_url
        notification_logger.info(f"Initializing device with server URL: {server_url}")

        # SSL/TLS configuration
        self.verify_ssl = verify_ssl
        self.cert_path = cert_path
        if not verify_ssl:
            notification_logger.warning("SSL verification disabled. This is not secure for production!")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Device identity
        self.device_name = 'weather-device-' + device_name if device_name else f"weather-device-{uuid.uuid4().hex[:8]}"
        self.device_type = self._generate_device_type()
        self.mac_address = self._generate_mac()
        self.gps_location = self._generate_gps()

        # Generate hardware fingerprints
        self.dmidecode_hash = self._generate_dmidecode_hash()
        self.lscpu_hash = self._generate_lscpu_hash()

        # Generate key pair for authentication
        self.private_key, self.public_key = self._generate_key_pair()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Session management
        self.authenticated = False
        self.status = None

        notification_logger.info(f"Device initialized: {self.device_name}")
        notification_logger.info(f"Device Type: {self.device_type}")
        notification_logger.info(f"dmidecode Hash: {self.dmidecode_hash}")
        notification_logger.info(f"lscpu Hash: {self.lscpu_hash}")
        notification_logger.info(f"MAC Address: {self.mac_address}")
        notification_logger.info(f"GPS Location: {self.gps_location}")
        notification_logger.info('Public key successfully generated')

    @classmethod
    def load_from_file(cls, filename, server_url=None, verify_ssl=True, cert_path=None):
        """Create a device by loading saved profile from a file"""
        notification_logger.info(f"Loading device profile from {filename}")
        try:
            with open(filename, 'r') as f:
                device_data = json.load(f)

            # Create an empty instance
            device = cls.__new__(cls)

            # Initialize with server settings
            device.server_url = server_url or device_data.get('server_url')
            device.verify_ssl = verify_ssl
            device.cert_path = cert_path
            if not verify_ssl:
                notification_logger.warning("SSL verification disabled. This is not secure for production!")
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Load device identity
            device.device_name = device_data.get('device_name')
            device.device_type = device_data.get('device_type')
            device.mac_address = device_data.get('mac_address')
            device.gps_location = device_data.get('gps_location')

            # Load hardware fingerprints
            device.dmidecode_hash = device_data.get('dmidecode_hash')
            device.lscpu_hash = device_data.get('lscpu_hash')

            # Load crypto keys
            device.public_key_pem = device_data.get('public_key_pem')

            # Deserialize the private key
            private_key_data = device_data.get('private_key')
            if private_key_data:
                device.private_key = serialization.load_pem_private_key(
                    private_key_data.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                device.public_key = device.private_key.public_key()

            # Session state
            device.authenticated = False
            device.status = None

            notification_logger.info(f"Device loaded from profile: {device.device_name}")
            notification_logger.info(f"Device Type: {device.device_type}")
            notification_logger.info(f"dmidecode Hash: {device.dmidecode_hash}")
            notification_logger.info(f"lscpu Hash: {device.lscpu_hash}")
            notification_logger.info(f"MAC Address: {device.mac_address}")
            notification_logger.info(f"GPS Location: {device.gps_location}")
            notification_logger.info('Public key successfully loaded')

            return device

        except Exception as e:
            notification_logger.error(f"Error loading device profile: {str(e)}")
            raise

    def save_to_file(self, filename):
        """Save the device profile to a file for later use"""
        notification_logger.info(f"Saving device profile to {filename}")

        # Serialize the private key to PEM format
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        device_data = {
            'server_url': self.server_url,
            'device_name': self.device_name,
            'device_type': self.device_type,
            'mac_address': self.mac_address,
            'gps_location': self.gps_location,
            'dmidecode_hash': self.dmidecode_hash,
            'lscpu_hash': self.lscpu_hash,
            'public_key_pem': self.public_key_pem,
            'private_key': private_key_pem,
        }

        try:
            with open(filename, 'w') as f:
                json.dump(device_data, f, indent=2)
            notification_logger.info(f"Device profile saved successfully")
            return True
        except Exception as e:
            notification_logger.error(f"Error saving device profile: {str(e)}")
            return False

    def _generate_device_type(self):
        """Generate a random IoT device type"""
        device_types = [
            "RaspberryPi",
            "Arduino",
            "ESP8266",
            "ESP32",
            "BeagleBone",
            "OrangePi",
            "JetsonNano",
            "RockPi",
            "WeatherStation",
            "SensorHub",
            "SmartEdge",
            "IoTGateway",
            "NodeMCU",
            "ParticlePhoton",
            "AdafruitFeather"
        ]
        return random.choice(device_types)

    def _generate_mac(self):
        """Generate a random MAC address"""
        mac = [
            0x00,
            0x16,
            0x3E,
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return ":".join(map(lambda x: f"{x:02x}", mac))

    def _generate_gps(self):
        """Generate random GPS coordinates (latitude,longitude)"""
        # Coordinates within Vietnam's boundaries
        lat = round(random.uniform(8.5, 23.5), 4)  # Vietnam latitude range
        lng = round(random.uniform(102.0, 109.5), 4)  # Vietnam longitude range
        return f"{lat},{lng}"

    def _generate_dmidecode_hash(self):
        """Run dmidecode and hash the output, or use alternative on Windows"""
        try:
            if os.name == "nt":  # Windows
                # Windows equivalent using PowerShell to get system information
                command = [
                    "powershell",
                    "-Command",
                    "Get-WmiObject -Class Win32_ComputerSystem | Out-String",
                ]
            else:  # Linux/Unix
                command = ["dmidecode", "-t", "system"]

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
            request_logger.debug(f"System info command executed successfully")

            # Hash the actual output
            return hashlib.sha256(output.encode()).hexdigest()
        except subprocess.SubprocessError as e:
            notification_logger.warning(f"Failed to execute system info command: {e}")
            # Fall back to the original method if command fails
            return self._generate_hash("dmidecode-output")

    def _generate_lscpu_hash(self):
        """Run lscpu and hash the output, or use alternative on Windows"""
        try:
            if os.name == "nt":  # Windows
                # Windows equivalent using PowerShell to get CPU information
                command = [
                    "powershell",
                    "-Command",
                    "Get-WmiObject -Class Win32_Processor | Out-String",
                ]
            else:  # Linux/Unix
                command = ["lscpu"]

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
            request_logger.debug(f"CPU info command executed successfully")

            # Hash the actual output
            return hashlib.sha256(output.encode()).hexdigest()
        except subprocess.SubprocessError as e:
            notification_logger.warning(f"Failed to execute CPU info command: {e}")
            # Fall back to the original method if command fails
            return self._generate_hash("lscpu-output")

    def _generate_hash(self, input_str):
        """Generate a hash from a string, used as fallback when commands fail"""
        # Combine the input string with device name for uniqueness
        data = f"{input_str}:{self.device_name}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _generate_key_pair(self):
        """Generate RSA key pair for secure communication"""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _make_https_request(self, method, url, json_data=None):
        """Make HTTPS request with proper SSL handling"""
        headers = {"Content-Type": "application/json"}
        request_args = {
            "verify": self.cert_path if self.cert_path else self.verify_ssl
        }

        try:
            if method.lower() == 'post':
                return requests.post(url, json=json_data, headers=headers, **request_args)
            elif method.lower() == 'get':
                return requests.get(url, headers=headers, **request_args)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
        except requests.exceptions.SSLError as e:
            notification_logger.error(f"SSL Error: {str(e)}")
            notification_logger.error("If using self-signed certificates, try with --no-verify-ssl option")
            raise
        except requests.exceptions.RequestException as e:
            notification_logger.error(f"Request Error: {str(e)}")
            raise

    def register(self):
        """Register the device with the server"""
        try:
            url = f"{self.server_url}/iot/register"
            notification_logger.info(f"Attempting to register device")
            request_logger.info(f"Registration URL: {url}")

            payload = {
                "device": self.device_name,
                "type": self.device_type,
                "public_key": self.public_key_pem,
                "dmidecode_hash": self.dmidecode_hash,
                "lscpu_hash": self.lscpu_hash,
                "MAC": self.mac_address,
                "gps": self.gps_location,
            }
            request_logger.debug(f"Registration payload: {json.dumps(payload, indent=2)}")

            response = self._make_https_request('post', url, payload)

            response_logger.info(f"Registration response status: {response.status_code}")
            response_logger.debug(f"Response headers: {response.headers}")
            response_logger.debug(f"Response body: {response.text}")

            if response.status_code == 201:
                notification_logger.info("Device registered successfully!")
                return True
            elif response.status_code == 409:
                notification_logger.info("Device already registered")
                return True
            else:
                notification_logger.error(f"Registration failed: {response.text}")
                return False

        except Exception as e:
            notification_logger.exception(f"Error during registration: {str(e)}")
            return False

    def login(self):
        """Authenticate the device with the server"""
        try:
            url = f"{self.server_url}/iot/login"
            notification_logger.info(f"Attempting to login")
            request_logger.info(f"Login URL: {url}")

            payload = {
                "device": self.device_name,
                "type": self.device_type,
                "public_key": self.public_key_pem,
                "dmidecode_hash": self.dmidecode_hash,
                "lscpu_hash": self.lscpu_hash,
            }
            request_logger.debug(f"Login payload: {json.dumps(payload, indent=2)}")

            response = self._make_https_request('post', url, payload)

            response_logger.info(f"Login response status: {response.status_code}")
            response_logger.debug(f"Response headers: {response.headers}")
            response_logger.debug(f"Response body: {response.text}")

            # If device is not registered (401), try registering it first
            if response.status_code == 401:
                notification_logger.warning("Device not registered. Attempting registration first.")
                if self.register():
                    notification_logger.info("Registration successful. Retrying login...")
                    # Try logging in again after successful registration
                    return self.login()  # Recursive call to try login again
                else:
                    notification_logger.error("Registration failed. Cannot proceed with login.")
                    return False

            # Login response should have a 202 status code with a challenge
            if response.status_code == 202:
                notification_logger.info("Login challenge received")
                challenge_data = response.json()
                encrypted_challenge = challenge_data.get("challenge")
                response_logger.debug(f"Received challenge: {encrypted_challenge[:20]}...")

                # Decrypt the challenge using our private key
                return self._process_challenge(encrypted_challenge)
            else:
                notification_logger.error(f"Login failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            notification_logger.exception(f"Error during login: {str(e)}")
            return False

    def _process_challenge(self, encrypted_challenge):
        """Process and respond to authentication challenge"""
        try:
            notification_logger.info("Processing authentication challenge")
            # Decode the base64 encrypted challenge
            encrypted_bytes = base64.b64decode(encrypted_challenge)
            request_logger.debug(f"Decoded challenge bytes length: {len(encrypted_bytes)}")

            # Decrypt the challenge using the private key
            request_logger.debug("Attempting to decrypt challenge with private key")
            decrypted_int = self.private_key.decrypt(
                encrypted_bytes, padding.PKCS1v15()
            )
            # Decode the bytes to get the original hex string
            decrypted_bytes = decrypted_int
            decrypted_challenge = decrypted_bytes.decode("utf-8")
            request_logger.debug(f"Decrypted challenge: {decrypted_challenge}")

            # Send the challenge response
            url = f"{self.server_url}/iot/challenge"
            notification_logger.info(f"Sending challenge response")
            request_logger.info(f"Challenge response URL: {url}")

            payload = {
                "device": self.device_name,
                "challenge": decrypted_challenge,
                "MAC": self.mac_address,
                "gps": self.gps_location,
            }
            request_logger.debug(f"Challenge requests payload: {json.dumps(payload, indent=2)}")

            response = self._make_https_request('post', url, payload)

            response_logger.info(f"Challenge response status: {response.status_code}")
            response_logger.debug(f"Response headers: {response.headers}")
            response_logger.debug(f"Response body: {response.text}")

            if response.status_code == 200:
                result = response.json()
                self.status = result.get("status")
                self.authenticated = True
                notification_logger.info(f"Challenge completed. Device status: {self.status}")
                return True
            else:
                notification_logger.error(
                    f"Challenge failed: {response.status_code} - {response.text}"
                )
                return False

        except Exception as e:
            notification_logger.exception(f"Error processing challenge: {str(e)}")
            return False

    def generate_weather_data(self):
        """Generate simulated weather data representative of Vietnam's climate"""
        # Temperature range for Vietnam (°C) - generally tropical and warm
        temperature = round(random.uniform(20, 35), 1)

        # Season adjustments (northern Vietnam has more seasonal variation)
        # Get current month to simulate seasonal changes
        current_month = time.localtime().tm_mon

        # Cooler temperatures in winter months (Dec-Feb) for northern regions
        if current_month in [12, 1, 2]:
            # Extract latitude from GPS to determine if in northern Vietnam
            lat = float(self.gps_location.split(',')[0])
            if lat > 17.0:  # Northern Vietnam
                temperature = round(random.uniform(15, 25), 1)

        # Humidity range for Vietnam (%) - typically very humid
        humidity = round(random.uniform(70, 95), 1)

        # Weather conditions common in Vietnam
        # Weight conditions based on the seasonal patterns
        if current_month in [5, 6, 7, 8, 9]:  # Rainy season (May-Sep)
            conditions = [
                "Heavy Rain", "Heavy Rain", "Rain", "Rain",
                "Thunderstorm", "Thunderstorm", "Cloudy",
                "Hot and Humid", "Hot and Humid"
            ]
        elif current_month in [11, 12, 1, 2]:  # Dry season with cooler weather in north
            conditions = [
                "Clear", "Clear", "Sunny", "Sunny", "Partly Cloudy",
                "Misty", "Light Rain", "Warm", "Humid"
            ]
        else:  # Transition months
            conditions = [
                "Sunny", "Cloudy", "Rain", "Light Rain",
                "Hot and Humid", "Warm", "Partly Cloudy", "Hazy"
            ]

        weather = random.choice(conditions)

        data = {
            "temperature": temperature,
            "humidity": humidity,
            "weather": weather,
        }
        request_logger.debug(f"Generated Vietnam-like weather data: {data}")
        return data

    def send_weather_data(self):
        """Send simulated weather data to the server"""
        if not self.authenticated:
            notification_logger.warning("Device not authenticated. Cannot send data.")
            return False

        weather_data = self.generate_weather_data()
        payload = {"device": self.device_name, **weather_data}

        try:
            url = f"{self.server_url}/iot/weather"
            notification_logger.info(f"Sending weather data")
            request_logger.info(f"Weather data URL: {url}")
            request_logger.debug(f"Weather data payload: {json.dumps(payload, indent=2)}")

            response = self._make_https_request('post', url, payload)

            response_logger.info(f"Weather data response status: {response.status_code}")
            response_logger.debug(f"Response headers: {response.headers}")
            response_logger.debug(f"Response body: {response.text}")

            if response.status_code in [200, 201]:
                notification_logger.info(f"Weather data sent successfully: {weather_data}")
                return True
            else:
                notification_logger.error(
                    f"Failed to send weather data: {response.status_code} - {response.text}"
                )
                return False

        except Exception as e:
            notification_logger.exception(f"Error sending weather data: {str(e)}")
            return False

    def run(self, interval=60, duration=None):
        """Run the device simulator with periodic data updates"""
        # Register and authenticate
        notification_logger.info("Starting device simulation")

        if not self.login():
            notification_logger.error("Authentication failed. Exiting.")
            return

        notification_logger.info(f"Starting weather data transmission every {interval} seconds")

        start_time = time.time()
        iteration = 0

        try:
            while True:
                # Send weather data
                self.send_weather_data()

                iteration += 1
                notification_logger.info(f"Completed iteration {iteration}")

                # Check if we've reached the duration limit
                elapsed = time.time() - start_time
                if duration and elapsed > duration:
                    notification_logger.info(
                        f"Reached duration limit of {duration} seconds ({elapsed:.1f}s elapsed)"
                    )
                    break

                # Sleep until next update
                notification_logger.info(f"Sleeping for {interval} seconds")
                time.sleep(interval)

        except KeyboardInterrupt:
            notification_logger.info("\nSimulation stopped by user")
        except Exception as e:
            notification_logger.exception(f"Error during simulation: {str(e)}")
        finally:
            notification_logger.info(f"Simulation completed after {iteration} iterations")


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="IoT Weather Simulator")
    parser.add_argument("-l", "--log-level", type=int, choices=[0, 1, 2], default=1,
                        help="Logging level: 0=None, 1=notifications only, 2=notifications+requests+responses")
    parser.add_argument("-d", "--device", help="Set a custom device ID")
    parser.add_argument("-s", "--server", help="Server URL (include https:// for secure connections)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable SSL certificate verification (not recommended for production)")
    parser.add_argument("--cert",
                        help="Path to custom certificate or CA bundle for SSL verification")

    # Add profile management arguments
    parser.add_argument("-o", "--save-profile", metavar="FILENAME",
                        help="Save device profile to file after initialization")
    parser.add_argument("-f", "--load-profile", metavar="FILENAME",
                        help="Load device profile from file instead of creating a new device")
    parser.add_argument("-i", "--interval", type=int, default=30,
                        help="Data transmission interval in seconds (default: 30)")
    parser.add_argument("--duration", type=int,
                        help="Run for specified duration in seconds then exit")

    args = parser.parse_args()

    # Configure logging based on level
    if args.log_level == 1:
        # Level 1: Show notifications only (default)
        notification_logger.setLevel(logging.INFO)
        request_logger.setLevel(logging.WARNING)
        response_logger.setLevel(logging.WARNING)
        print("Log level 1: Showing notifications only")
    elif args.log_level == 2:
        # Level 2: Show notifications + requests + responses
        notification_logger.setLevel(logging.INFO)
        request_logger.setLevel(logging.DEBUG)
        response_logger.setLevel(logging.DEBUG)
        print("Log level 2: Showing notifications, requests, and responses")
    else:
        # Level 0: Show nothing
        notification_logger.setLevel(logging.WARNING)
        request_logger.setLevel(logging.WARNING)
        response_logger.setLevel(logging.WARNING)

    # Check if server URL is using HTTPS
    if args.server and not args.server.startswith(('http://', 'https://')):
        args.server = f"https://{args.server}"
        notification_logger.info(f"No protocol specified, using HTTPS: {args.server}")

    # Create a device simulator - either from file or as new device
    if args.load_profile:
        device = WeatherIoTSimulator.load_from_file(
            args.load_profile,
            server_url=args.server,  # Override server URL if provided
            verify_ssl=not args.no_verify_ssl,
            cert_path=args.cert
        )
    else:
        # Create a device simulator with custom device name if provided
        device = WeatherIoTSimulator(
            args.server,
            device_name=args.device,
            verify_ssl=not args.no_verify_ssl,
            cert_path=args.cert
        )

    # Save profile if requested
    if args.save_profile:
        device.save_to_file(args.save_profile)

    # Run the simulation with specified interval
    device.run(interval=args.interval, duration=args.duration)
