const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const passport = require('passport'), LocalStrategy = require('passport-local').Strategy;
const cors = require('cors');
const mongoose =require('mongoose');
const Schema = mongoose.Schema;
const crypto = require('crypto');
const createHash = crypto.createHash;
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const User = require('./models/user');
const SECRET = 'allanstrangemadethis'; ///change to environment variable
const compose = require('composable-middleware')
const router = express.Router();


//----------------
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(cors());
app.use('/', router);


//------------------

mongoose.connect('mongodb://localhost/splitmyride');


//-------------------------
const seed = () => {
	User.find({}).remove().then(() => {
		const users = [{
			displayName: 'alice',
			email: 'alice@test.com',
			password: '1234',
		},{
			displayName:'bob',
			email: 'bob@test.com',
			password: '1234'
		}];

		User.create(users, (err, users_)=>{
			if(err){ console.log("Error " + err) }
			console.log("success " + users_.length + " users created") ;
			console.log(users);
		});
	});
};


//-------------------------
const sendUnauthorized = (req, res) => {
	res.status(401).json({message: 'Unauthorized'});
};

const validateJwt = expressJwt({
	secret: SECRET,
	fail: sendUnauthorized
});


app.get('/', function(req,res){

	User.find({} , (err,users_)=>{
		console.log("I am triggered");
		res.json(users_);
	})
});


app.get('/cleardb', function(req,res){
	mongoose.connection.db.dropDatabase();
});


const isAuthenticated = () =>{
	
	return compose()
			
			.use((req,res,next) => {
				validateJwt(req,res,next);
			})

			.use((req,res,next) => {
				const {email} = req.user;

				User.findOne({email},'-salt -hashedPassword',(err, user)=>{

					if (err) return next(err);

					if(!user) return sendUnauthorized(req,res);

			 		req.user = user;

			 		console.log(user)
			 		
			 		next();
			});
	});
}

//const Authenticated = isAuthenticated().bind(this);

passport.serializeUser(function(user, done){
	done(null, user.email);
});

passport.deserializeUser(function(email,done){
	User.findOne({email}, function(err,user){
		done(err,user);
	});
});


//------------------------------------

passport.use(new LocalStrategy({

	usernameField: 'email',
	session: false
 
	},

	function(email,password, done){

		User.findOne({ email }, function(err,user){
			if(err){
				console.log("Auth error" + err);
				return done(err);}
			if(!user){
				console.log("Incorrect Email");
				return done(null, false, {message: 'Incorrect Email'});
			}
			if(!user.authenticate(password)){
				console.log("Incorrect password");
				return done(null, false, {message: 'Incorrect Password'});
			}
			return done(null, user);
		});

	}

	));

//handle the token
app.use((req,res,next)=>{

	const header = req.headers.authorization;
	

	//Authorization : Bearer [token]

	if (header) 
	{
		const splitHeader = header.split(' ');

		if(splitHeader.length != 2 && splitHeader[0] !== 'Bearer')
		{
			next();
		}
		else
		{
			const decoded = jwt.decode(splitHeader[1]);			
			next();
		}
	}
	else
	{
		next();
	}
});

//------------------------------------
//authentication end point
app.post('/login', (req,res,next) => {
  passport.authenticate('local', { session : false },(err,user)=>{
  		const access_token = jwt.sign({
			id: user._id,
  			email: user.email
  		}, SECRET,{
  			expiresIn: 60 * 60
  		});

  		res.json({
  			access_token
  		});

	})(req,res,next);
  });

app.post('/signup', (req,res)=> {
	const user = req.body;
	console.log(user);

	//check if user exists
	User.find({ email: user.email}).then(users =>{
		if (users.length === 0)
		{
			//create user
			User.create(user).then(user_ => {
				const access_token = jwt.sign({
					id: user_._id,
  					email: user_.email
  				}, SECRET,{
  					expiresIn: 60 * 60
  				});
  			res.json({ access_token });
  			})
		}
		else
		{
			//return error
			res.json({
				status: 'Error',
				message: 'Email already exists'
			});

		}
	})
})



//-------------------------------------
//basic routes
app.use('/api', require('./api') (isAuthenticated));


//seed();
//if there is an error
app.use((err, req, res, next)=>{
	res.status(err.status || 500);
	
	res.json({
		'error': {
			message: err.message,
			error: err
		}
	});
	next();
})

module.exports = router;

app.listen(8000);