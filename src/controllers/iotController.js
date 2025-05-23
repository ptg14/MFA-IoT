const crypto = require('crypto');

class IoTController {
    constructor(database) {
        this.database = database;
    }

    async registerIoTDevice(req, res) {
        try {
            const { device, type, public_key, dmidecode_hash, lscpu_hash, MAC, gps } = req.body;

            if (!device) {
                return res.status(400).json({ message: 'Device ID is required' });
            }

            // Check if device already exists
            const deviceExists = await this.database.fetchQuery(
                'SELECT * FROM iot WHERE device = ?',
                [device]
            );

            if (deviceExists.length > 0) {
                console.log('Device already registered:', device);
                return res.status(409).json({ message: 'Device already registered' });
            }

            // Register the new device
            const result = await this.database.executeQuery(
                `INSERT INTO iot (device, type, public_key, dmidecode_hash, lscpu_hash, MAC, gps)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [device, type, public_key, dmidecode_hash, lscpu_hash, MAC, gps]
            );
            console.log('Device successfully registered:', device);

            res.status(201).json({
                message: 'IoT device registered successfully',
                success: true,
                deviceId: device
            });
        } catch (error) {
            res.status(500).json({
                message: 'Error registering IoT device',
                error: error.message
            });
        }
    }

    async authenticateIoTDevice(req, res) {
        try {
            const { device, type, public_key, dmidecode_hash, lscpu_hash } = req.body;

            // Check if device exists and credentials match
            const deviceData = await this.database.fetchQuery(
                'SELECT * FROM iot WHERE device = ?',
                [device]
            );

            if (deviceData.length === 0) {
                console.log('Device not registered:', device);
                return res.status(401).json({
                    message: 'Device not registered',
                    success: false
                });
            }

            const storedDevice = deviceData[0];

            // Verify device credentials
            if (type !== storedDevice.type ||
                storedDevice.public_key !== public_key ||
                storedDevice.dmidecode_hash !== dmidecode_hash ||
                storedDevice.lscpu_hash !== lscpu_hash) {
                await this.database.executeQuery(
                    'UPDATE iot SET status = ? WHERE device = ?',
                    ['Invalid', device]
                );
                console.log('Device details do not match:', device);
                return res.status(401).json({
                    message: 'Authentication failed: device details do not match',
                    success: false
                });
            }

            const challengeToken = crypto.randomBytes(32).toString('hex');
            console.log('Challenge token:', challengeToken);

            await this.database.executeQuery(
                'UPDATE iot SET challenge = ? WHERE device = ?',
                [challengeToken, device]
            );

            const encryptedChallenge = crypto.publicEncrypt(
                {
                    key: storedDevice.public_key,
                    padding: crypto.constants.RSA_PKCS1_PADDING
                },
                Buffer.from(challengeToken)
            ).toString('base64');
            // console.log('Encrypted challenge:', encryptedChallenge);

            res.status(202).json({
                message: 'Required challenge',
                challenge: encryptedChallenge,
            });
        } catch (error) {
            const deviceId = req.body && req.body.device;

            if (deviceId) {
                await this.database.executeQuery(
                    'UPDATE iot SET status = ? WHERE device = ?',
                    ['Invalid', deviceId]
                );
            }
            res.status(500).json({
                message: 'Error authenticating IoT device',
                error: error.message
            });
        }
    }

    async verifyChallenge(req, res) {
        try {
            const { device, challenge, MAC, gps } = req.body;

            // Check if device exists
            const deviceData = await this.database.fetchQuery(
                'SELECT * FROM iot WHERE device = ?',
                [device]
            );

            if (deviceData.length === 0) {
                console.log('Device not registered:', device);
                return res.status(401).json({
                    message: 'Device not registered',
                    success: false
                });
            }

            const storedDevice = deviceData[0];

            if (challenge !== storedDevice.challenge) {
                await this.database.executeQuery(
                    'UPDATE iot SET status = ? WHERE device = ?',
                    ['Invalid', device]
                );
                console.log('Failed challenge verification:', device);
                return res.status(401).json({
                    message: 'Invalid challenge',
                    success: false
                });
            }
            let status = 'Verified';
            let message = 'Challenge verified successfully';

            if (MAC !== storedDevice.MAC || gps !== storedDevice.gps) {
                console.log('Suspicious device detected:', device);
                status = 'Suspicious';
                message = 'Suspicious device';
            }

            await this.database.executeQuery(
                'UPDATE iot SET status = ?, last_auth_time = ? WHERE device = ?',
                [status, new Date().toISOString(), device]
            );

            res.status(200).json({
                message: message,
                status: status,
                success: true
            });
        } catch (error) {
            const deviceId = req.body && req.body.device;

            if (deviceId) {
                await this.database.executeQuery(
                    'UPDATE iot SET status = ? WHERE device = ?',
                    ['Invalid', deviceId]
                );
            }
            res.status(500).json({
                message: 'Error verifying challenge',
                error: error.message
            });
        }
    }
}

module.exports = IoTController;
