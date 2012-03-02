

Facebook NodeJS SDK (v.3.1.1)
==========================

The [Facebook Platform](http://developers.facebook.com/) is
a set of APIs that make your app more social

This repository contains the open source NodeJS SDK that allows you to access Facebook Platform from your NodeJS app. Except as otherwise noted, the Facebook NodeJS SDK
is licensed under the Apache Licence, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html)


About
=========

This is a almost line for line port of the Facebook SDK for NodeJS written in coffeescript
Once it's stable I plan on releasing it on NPM
At the moment there's a implementation for Connect/Express that includes a middleware so you can do fun stuff like this

	exports.index = function(req, res){
	 // The facebook middleware let's you access the SDK
	  req.facebook.getUser(function(err, uid){ // function names are the same but some now require callbacks
			if(uid == 0){
				res.redirect(req.facebook.getLoginUrl()) // In the future there will be a facebook.requireLogin() function that does for you
			}
			else{
				// once you call getUser it's cached in the session
				// and you can access the .me object directly from here 
				// you may also call req.facebook.api('/me', callback) to get the same results
				res.render('index', {title: 'Yo', body: "Hello " + req.facebook.me.first_name + "!"}) 
			}
	  })
	};
