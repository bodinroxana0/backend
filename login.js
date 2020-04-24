var mysql = require('mysql');
var express = require('express');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var morgan = require('morgan');
var bodyParser = require('body-parser');
var path = require('path');
var app = express();
const cors = require('cors');
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
var Buffer = require('buffer').Buffer;
var zlib = require('zlib');
var fs = require("fs");
var https = require('https');
var helmet = require('helmet');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
var sess; //to store session

// https.createServer({
//   key: fs.readFileSync('server.key'),
//   cert: fs.readFileSync('server.cert')
// }, app)
// .listen(3001, function () {
//   console.log('Example app listening on port 3000! Go to https://localhost:3000/')
// })
//for middleware protection
app.use(helmet());
//use cors to allow cross origin resource sharing
app.use(
  cors({
    origin: 'https://comunitate.netlify.app',
    credentials: true,
  }));
//mysql connection
var connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "isawsuits2@",
  database: "community"
});
connection.connect(function(err) {
	if (err) throw err;
	console.log('You are now connected with mysql database...');
  });
//json settings for sending more amount of data between client and server
app.use(bodyParser.urlencoded());
app.use(bodyParser.json({limit:"50mb",extended:true}));

//server settings
var server = app.listen(3000, "127.0.0.1", function () {

	var host = server.address().address
	var port = server.address().port
  
	console.log("Example app listening at http://%s:%s", host, port)
 });
///////////////////encrypt
 function encrypt(text) {
	let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
	let encrypted = cipher.update(text);
	encrypted = Buffer.concat([encrypted, cipher.final()]);
	return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
   }
///////////////////decrypt
 function decrypt(P_iv,data,key_d) {
	let iv_decrypt = Buffer.from(P_iv, 'hex');
	let encryptedText = Buffer.from(data, 'hex');
	let decipher = crypto.createDecipheriv(algorithm,Buffer.from(key_d), iv_decrypt);
	let decrypted = decipher.update(encryptedText);
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return decrypted.toString();
   }
// set morgan to log info about our requests for development use.
app.use(morgan('dev'));
// initialize cookie-parser to allow us access the cookies stored in the browser. 
app.use(cookieParser('This is a secret'));
// initialize express-session to allow us track the logged-in user across sessions.
app.use(session({
    key: 'user_sid',
    secret: 'This is a secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 600000
    }
}));
// This middleware will check if user's cookie is still saved in browser and user is not set, then automatically log the user out.
// This usually happens when you stop your express server after login, your cookie still remains saved in the browser.
app.use((req, res, next) => {
    if (req.cookies.user_sid && !req.session.username) {
        res.clearCookie('user_sid');        
    }
    next();
});

// //rest api to get all customers
app.get('/users', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	connection.query('select * from user', function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   //console.log(results)
	 });
 });
 app.get('/services', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	connection.query('select * from services', function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   //console.log(results)
	 });
 });
 app.get('/provider', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id', function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   //console.log(results)
	 });
 });
 app.get('/searchprovider/:service/:city', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var service = req.params.service;
	var city = req.params.city;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE ServiceName= ? AND City= ?',[service,city], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/searchprovider1/:domain', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var domain = req.params.domain;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE ServiceDomain= ?',[domain], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/searchprovider2/:service', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var service = req.params.service;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE ServiceName= ?',[service], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/searchprovider3/:region', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var region = req.params.region;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE Region= ?',[region], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/searchprovider4/:city', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var city = req.params.city;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE City= ?',[city], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/searchprovider5/:domain/:region', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var domain = req.params.domain;
	var region = req.params.region;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE ServiceDomain= ? AND Region= ?',[domain,region], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/searchprovider6/:domain/:city', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var domain = req.params.domain;
	var city = req.params.city;
	connection.query('SELECT * FROM community.provider INNER JOIN community.services ON community.provider.services_Id = community.services.Id WHERE ServiceDomain= ? AND City= ?',[domain,city], function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   console.log(results)
	 });
 });
 app.get('/cities', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	connection.query('select * from cities', function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	   //console.log(results)
	 });
 });
 app.get('/counties', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	connection.query('select * from counties', function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	  // console.log(results)
	 });
 });
 app.get('/cities/:county_name', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var county_name = req.params.county_name;
	//console.log(county_name);
	if(county_name){
		connection.query('select * from cities  WHERE county_name = ?', [county_name], function (error, results, fields) {
		if (error) throw error;
		res.end(JSON.stringify(results));
		//console.log(results)
		});
	}
 });
 app.get('/domain', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	connection.query('select * from services', function (error, results, fields) {
	   if (error) throw error;
	   res.end(JSON.stringify(results));
	  // console.log(results);
	 });
 });
 app.get('/services/:domain', function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var domain = req.params.domain;
	if(domain){
		connection.query('select * from services  WHERE ServiceDomain = ?', [domain], function (error, results, fields) {
		if (error) throw error;
		res.end(JSON.stringify(results));
		});
	}
 });
 app.get('/phone/:username',function (req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var username = req.params.username;
	if(username){
		connection.query('select Phone from provider WHERE UserName = ?', [username], function (error, results, fields) {
		if (error) throw error;
		try
		{
			console.log(sess.username);
			if(sess.username!=0)
				res.end(JSON.stringify(results));
			else
				res.end("Null");
		}
		catch
		{ 
			res.end("Null");
		}
		});
	}
 });
 app.post('/LoginFB', function(req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var username = req.body.name;
	var email = req.body.email;
	var userID = req.body.userID;
	sess=req.session;
	sess.username=userID;
	console.log('Cookie: '+sess.username);
	res.send('Bun venit, '+username+" !");
});
app.post('/LoginGoogle', function(req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var username = req.body.username;
	var email = req.body.email;
	var userID = req.body.Googleid;
	sess=req.session;
	sess.username=userID;
	console.log('Cookie: '+sess.username);
	res.end('Bun venit, '+username+" !");
});
 //Login + setarea session 
app.get('/users/:UserName/:Password', function(req, res) {
	res.setHeader('Access-Control-Allow-Origin', 'https://comunitate.netlify.app');
	var username = req.params.UserName;
	var password = req.params.Password;
	if (username && password) {
		connection.query('SELECT * FROM user WHERE UserName = ? ', [username], function(error, results, fields) {
			if (results.length > 0) {
				console.log(results[0].PasswordIV);
				console.log(results[0].PasswordData);
				var kd=JSON.parse(zlib.unzipSync(Buffer.from(results[0].Key,'base64')));
				console.log(kd.data);
				var decrypt_pass=decrypt(results[0].PasswordIV,results[0].PasswordData,kd);
				console.log(decrypt_pass);
				if(password==decrypt_pass)
				{
					sess=req.session;
					sess.username=username;//$_SESSION['username']-create new session
					//console.log('sesiunea e setata'+sess.username);
					res.send('Bun venit, '+username+" !");
				}
				else 
					res.send('Nume sau parolă incorectă!');
			}			
			res.end();
		});
	} else {
		res.send('Introduceți datele!');
		res.end();
	}
	});
app.post('/SignUpUser', function(req, res) {
		var encrypted=encrypt(req.body.password);
		var k = zlib.gzipSync(JSON.stringify(key)).toString('base64');
		const newUser = {
		UserName: req.body.userName,
		PasswordIV: encrypted.iv , 
		PasswordData: encrypted.encryptedData,
		Key: k ,
		FirstName: req.body.firstName, 
		LastName: req.body.lastName, 
		Email: req.body.email,
		Phone: req.body.phone,
		City: req.body.city,
		Region: req.body.region,
		Birthdate: req.body.birthdate
		};
		console.log(newUser);
		connection.query('INSERT INTO user SET ?', newUser, function (error, results, fields) {
			if (error) throw error;
			res.end(JSON.stringify(results));
		  });
	});
app.post('/SignUpProvider', function(req, res) {
		var encrypted=encrypt(req.body.password);
		var k = zlib.gzipSync(JSON.stringify(key)).toString('base64');
		const newUser = {
		UserName: req.body.userName,
		PasswordIV: encrypted.iv , 
		PasswordData: encrypted.encryptedData,
		Key: k ,
		FirstName: req.body.firstName, 
		LastName: req.body.lastName, 
		Email: req.body.email,
		Phone: req.body.phone,
		City: req.body.city,
		Region: req.body.region,
		Birthdate: req.body.birthdate,
		Services_Id:req.body.services_Id,
		Description:req.body.description,
		Photo:req.body.path
		};
		//console.log(newUser);
		connection.query('INSERT INTO provider SET ?', newUser, function (error, results, fields) {
			if (error) {
				if(error.code == 'ER_DUP_ENTRY' || error.errno == 1062)
				{
					res.send('This username is taken. Try another one!');
				}
				else{
					throw error;
				}

			}
			res.end(JSON.stringify(results));
		  });
	});
app.post('/Docs', function(req, res) {
		var img= req.body.path2;
		var username=req.body.userName;
		var id;
		var elem;
		var res;
		console.log(username);
		connection.query('SELECT Id FROM provider WHERE UserName = ? ', [username], function (error, results, fields) {
			if (error) throw error;
			id=results[0].Id;
			console.log(id);
		img.forEach(element => {
			elem={
				IdProvider: id,
				Image:element
			};
			connection.query('INSERT INTO docs SET ?', elem, function (error, results, fields) {
				if (error) throw error;
				res.end(JSON.stringify(results));
			  });
		});
	});
});
// route for user logout
app.get('/logout', (req, res) => {
	console.log('Cookie before: '+sess.username);
	req.session.destroy((err) => {
        if(err) {
            res.end(err);
		}
		try{
			sess.username=0;
			console.log('Cookie after: '+sess.username);
			res.end('ok');
		}
		catch{
			
		}
		
	});
});