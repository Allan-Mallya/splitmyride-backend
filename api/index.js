const express = require('express');
const router = express.Router();

module.exports = isAuthenticated => {
	
	router.use('/users', require('./users')(isAuthenticated));

	return router;
};


