const express = require('express');
const router = express.Router();

module.exports = isAuthenticated => {

	router.use('/me', isAuthenticated(), (req,res)=> {

			console.log('I am triggered');
			
			res.json(req.user);
	});

	return router;
};


