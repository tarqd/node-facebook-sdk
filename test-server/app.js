
/**
 * Module dependencies.
 */

var express = require('express')
  , routes = require('./routes')
  , fs = require('fs')
  , coffee = require('coffee-script')
  , facebook = require('../index.coffee').ConnectFacebook.facebook


var privateKey = fs.readFileSync('privatekey.pem').toString();
var certificate = fs.readFileSync('certificate.pem').toString();
var app = module.exports = express.createServer(/*{key: privateKey, cert: certificate}*/);

// Configuration

app.configure(function(){
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.cookieParser());
  app.use(express.session({ secret: 'your secret here' }));
  var middleware = facebook({
		appId: '140469049354669',
		appSecret: 'b7547cadb8a95cbd1ba09a70c4a17ebb'
	});
  app.use(middleware);
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));

});

app.configure('development', function(){
  app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function(){
  app.use(express.errorHandler());
});

// Routes



app.get('/', routes.index);



app.listen(3000);
console.log("Express server listening on port %d in %s mode", app.address().port, app.settings.env);
