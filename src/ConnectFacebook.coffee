BaseFacebook = require __dirname + '/base_facebook.coffee'
_ = require('underscore')

class ConnectFacebook extends BaseFacebook
	constructor: (config) ->
		@_request = config.connect.request
		@_response = config.connect.response
		super config
	
	setPersistentData: (name, value) ->
		console.log("set #{name} = #{value}")
		@_request.session._facebook[name] = value
	
	getPersistentData: (name, defaultValue) -> 
		defaultValue = defaultValue || false
		if(_.has(@_request.session._facebook, name))
			return @_request.session._facebook[name]
		else
			return defaultValue
	
	clearPersistentData: (name) -> 
		delete @_request.session._facebook['name']
		
	clearAllPersistentData: () -> 
		@_request.session._facebook = {}
	
	getHost: () ->
		return (@_request.headers['host']) || "#{@_request.server.address().ip}:#{@_request.server.address().port}"
	# There should really 
	getCurrentUrl: () -> 
		# hack to dermine if we're using https
		protocol = if @_request.app['cert']  then 'https' else 'http'
		host = @getHost()
		path = require('url').parse(@_request.url).pathname
		return "#{protocol}://#{host}#{path}"	
	
	# These are unique to the node-facebook port
	setCookie: (name, value, expire, path, domain) -> 
		if(expire == undefined) then expire = 0
		if(path == undefined) then path = '/'
		if(domain == undefined) then domain = '.' + @getHost()
		@_response.cookie(name, value, {expires: expire, path: path, domain: domain})
	
	removeCookie: (name) -> 
		@_response.clearCookie(name)
	
	getCookie: (name) -> 
		return @_request.cookies[name]
		
	getRequestParameter: (name) ->
		console.log("getparam(): name=#{name}, val: #{@_request.param(name)}")
		return @_request.param(name)
		
	errorLog: (error) ->
		console.log("ERROR: #{error}")
	
		


# Exports the class and the middleware
# We create a new instance per request like the php version
module.exports = {
	ConnectFacebook: ConnectFacebook,
	
	facebook: (@config) -> 
		console.log('fb called')
		me = this
		return (req, res, next) ->
			console.log('middleware called')
			# start the persistent store
			if !req.session._facebook
				req.session._facebook = {}
			req.facebook = new ConnectFacebook(_.extend(me.config, {connect:{request: req,  response: res}}))
			next()
		
		
}