const express = require('express');
const router = express.Router();
const WeatherController = require('../controllers/weatherController');
const database = require('../utils/database');

// Create controller with database access
const weatherController = new WeatherController(database);

router.get('/weather', weatherController.getWeatherData.bind(weatherController));

module.exports = router;
