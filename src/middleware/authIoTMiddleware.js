const database = require('../utils/database');

async function validateIoTDevice(req, res, next) {
    const { device } = req.body;

    if (!device) {
        return res.status(400).json({ message: 'Device ID is required' });
    }

    try {
        // Check if device exists and is authenticated
        const deviceData = await database.fetchQuery(
            'SELECT * FROM iot WHERE device = ?',
            [device]
        );

        // Add validation results to the request object
        req.deviceValidation = {
            isValid: deviceData.length > 0,
            deviceData: deviceData[0] || null
        };

        if (!req.deviceValidation.isValid) {
            return res.status(401).json({
                message: 'Device not registered',
                success: false
            });
        }

        // Check if device is authenticated (status is Verified or Suspicious)
        if (req.deviceValidation.deviceData.status !== 'Verified' &&
            req.deviceValidation.deviceData.status !== 'Suspicious') {
            return res.status(401).json({
                message: 'Device not authenticated or invalid',
                success: false
            });
        }

        next();
    } catch (error) {
        res.status(500).json({
            message: 'Error authenticating IoT device',
            error: error.message
        });
    }
}

module.exports = {
    validateIoTDevice
};
