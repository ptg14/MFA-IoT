const express = require('express');
const router = express.Router();
const IoTController = require('../controllers/iotController');
const WeatherController = require('../controllers/weatherController');
const database = require('../utils/database');
const { validateIoTDevice } = require('../middleware/authIoTMiddleware');

const iotController = new IoTController(database);

router.post('/register', iotController.registerIoTDevice.bind(iotController));
router.post('/login', iotController.authenticateIoTDevice.bind(iotController));
router.post('/challenge', iotController.verifyChallenge.bind(iotController));

// Only authenticated IoT devices can post weather data
const weatherController = new WeatherController(database);

router.post('/weather', validateIoTDevice, weatherController.addWeatherData.bind(weatherController));

module.exports = router;
