class WeatherController {
    constructor(database) {
        this.database = database;
    }

    async getWeatherData(req, res) {
        try {
            // Modified query to join with iot table to get device status and GPS
            const weatherData = await this.database.fetchQuery(
                `SELECT m.device, m.temperature, m.humidity, m.weather, m.update_time,
                   i.status, i.type, i.gps
            FROM manage m
            JOIN iot i ON m.device = i.device
            ORDER BY m.update_time DESC`
            );

            // Group by device (to get latest reading for each device)
            const deviceMap = new Map();
            weatherData.forEach(item => {
                if (!deviceMap.has(item.device) ||
                    new Date(item.update_time) > new Date(deviceMap.get(item.device).update_time)) {
                    deviceMap.set(item.device, item);
                }
            });

            const latestData = Array.from(deviceMap.values());

            res.status(200).json(latestData);
        } catch (error) {
            res.status(500).json({ message: 'Error fetching weather data', error: error.message });
        }
    }

    async addWeatherData(req, res) {
        try {
            const { device, temperature, humidity, weather } = req.body;

            if (!device) {
                return res.status(400).json({ message: 'Device ID is required' });
            }

            // Check if the device exists in the IoT table
            const deviceExists = await this.database.fetchQuery(
                'SELECT * FROM iot WHERE device = ?',
                [device]
            );

            if (deviceExists.length === 0) {
                return res.status(404).json({ message: 'Device not found' });
            }

            // Update or insert weather data
            const result = await this.database.executeQuery(
                `INSERT INTO manage (device, temperature, humidity, weather, update_time)
                 VALUES (?, ?, ?, ?, datetime('now'))`,
                [device, temperature, humidity, weather]
            );

            res.status(201).json({
                message: 'Weather data added successfully',
                success: true
            });
        } catch (error) {
            res.status(500).json({
                message: 'Error adding weather data',
                error: error.message
            });
        }
    }
}

module.exports = WeatherController;
