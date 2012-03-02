rest = require('restler')
FacebookApiError = require(__dirname + '/errors/FacebookApiError.coffee')
crypto = require('crypto')
_ = require('underscore')
_s = require('underscore.string')
qs = require('querystring')
uri = require('url')
FNI = new Error('Function not implemented. You must extend this class in order to use it')



class BaseFacebook
	VERSION: '3.1.1'
	USER_AGENT: 'facebook-nodgetPeristentDate-3.1'
	DROP_QUERY_PARAMETERS: ['code', 'state', 'signed_request']
	DOMAIN_MAP: {
		'api'       : 'https://api.facebook.com/',	    'api_video' : 'https://api-video.facebook.com/',	    'api_read'  : 'https://api-read.facebook.com/',	    'graph'     : 'https://graph.facebook.com/',	    'graph_video' : 'https://graph-video.facebook.com/',	    'www'       : 'https://www.facebook.com/'
	}
	REST_OPTIONS: {
		headers: {
			'User-Agent': @USER_AGENT
		}
	}
	constructor: (config) ->
		@appId = config.appId
		@appSecret = config.appSecret
		@state = @getPersistentData('state')
		@state = @state || null
	
	getAccessToken: (cb) ->
		if !@accessToken
			@accessToken = @getApplicationAccessToken()
			@getUserAccessToken (err, user_access_token) =>
				if user_access_token
					@accessToken = user_access_token
				cb(err, user_access_token)
		else
			cb(null, @accessToken)
	
		
	getUserAccessToken: (cb) ->
		signed_request = @getSignedRequest()
		if signed_request
			if signed_request['oauth_token'] 
				access_token = signed_request['access_token']
				@setPersistentData('access_token', access_token)
				cb(null, access_token)
			else if signed_request['code']
				code = signed_request['code']
				@getAccessTokenFromCode code,'',(err, access_token) =>
					if access_token
						@setPersistentData('code', code)
						@setPersistentData('access_token', access_token)
					cb(err, access_token)
			else
				@clearAllPeristentData()
				cb(null, false)
		else # if no signed request
			code = @getCode()
			if code && code != @getPersistentData('code')
				@getAccessTokenFromCode code, @getCurrentUrl(), (err, access_token) =>
					if access_token
						@setPersistentData('code', code)
						@setPersistentData('access_token', access_token)
					else
						@clearAllPersistentData()
					cb(err, access_token)
			else
				cb(null,@getPersistentData('access_token'))
			
			

	
	getUser: (cb) ->
		if @user
			cb(null,@user)
		else
			@getUserFromAvailableData (err, user) ->
				console.log('got user from data')
				console.dir([err, user])
				console.log('------------------')
				cb(err, user)
	
	getUserFromAvailableData: (cb) ->
		signed_request = @getSignedRequest()
		if signed_request
			if signed_request.user_id
				@setPersistentData('user_id', signed_request.user_id)
				@user = signed_request.user_id
				cb(null,signed_request.user_id)
			else
				@clearPersistentData()
				@user = 0
				@me = undefined
				cb(null, 0)
		else
			user = @getPersistentData('user_id', 0)
			p_access_token = @getPersistentData('access_token')
			@getAccessToken (err, access_token) =>
				if access_token && access_token != @getApplicationAccessToken() && !(!!user && p_access_token == access_token)
					@getUserFromAccessToken (err, user) =>
						console.log('getting user from access token')
						console.dir(user)
						if(user)
							@setPersistentData('user_id', user['id'])
							@setPersistentData('user', user)
							@user = user['id']
							@me = user
							console.log('the user is set to ' + user['id'])
						else
							@clearPersistentData()
							@user = 0
							@me = undefined
						console.log('calling cb with @user = ' + @user)
						cb(err, @user)
					
				else
					@user = 0
					@me = undefined
					cb(null, user)
			
	
	getLoginUrl: (params) ->
		params = params || {}
		@establishCSRFTokenState()
		current_url = @getCurrentUrl()
		if params['scope'] && _.isArray(params['scope'])
			params['scope'] = params['scope'].join(',')
		return @getUrl(
					'www',
					'dialog/oauth',
					_.extend({
						client_id: @appId,
						redirect_uri: current_url,
						state: @state
					}, params))
	
	getLogoutUrl: (params) ->
		params = params || params
		current_url = @getCurrentUrl()
		return @getUrl(
					'www',
					'logout.php',
					_.extend({
						next: current_url,
						access_token: @getAccessToken
					}, params))
	
	getLoginStatusUrl: (params) ->
		params = params || {}
		current_url = @getCurrentUrl()
		return @getUrl('www', 'extern/login_status.php', {'api_key' : @appId,'no_session' : current_url, 'no_user' : current_url, 'ok_session' : current_url,'session_version' : 3 })
	
	
	# polymorphic				
	api: () ->
		if _.isArray(arguments[0])
			@_restserver(arguments[0])
		else
			@_graph.apply(this, arguments)
			
	
	getSignedRequestCookieName: () ->
		return 'fbsr_' + @appId
	
			   
	getMetadataCookieName: () ->
		return 'fbm_' + @appId
	
	getUserFromAccessToken: (cb) ->
		@api '/me',{fields: 'first_name,last_name,id,username,gender'}, (err, user_info) ->
			cb(err, user_info)
	
	
	  
	getApplicationAccessToken: () ->
		return @appId + '|' + @appSecret
	
	establishCSRFTokenState: () ->
		if (!@state) 
			@state = crypto.createHash('md5')
						 .update(Math.random().toString())
						 .digest('hex')
		@setPersistentData('state', @state)
		
			   	   
	
	getAccessTokenFromCode: (code, redirect_uri, cb) ->
		if code == '' then cb(null, false)
		if (redirect_uri == null) 
			redirect_uri = @getCurrentUrl()
			
		@_oauthRequest @getUrl('graph', '/oauth/access_token'),{
				'client_id' : @appId,
				'client_secret' : @appSecret,
				'redirect_uri' : redirect_uri,
				'code' : code
			}, (err, access_token_response) ->
				if(err) then cb(err, null)
				if (access_token_response == '')
					cb(null, false)
				response_params = qs.parse(access_token_response)
				ret = false
				if response_params && response_params['access_token'] then ret = response_params['access_token']
				cb(null, ret)
		
	
			   
	_restserver: (params, cb) ->
		params['api_key'] = @appId
		params['format'] = 'json-strings'

		@_oauthRequest @getApiUrl(params['method']), params, (err, result) =>
			#  results are returned, errors are thrown
			try
				result = JSON.stringify(result)
				if (_.isObject(result) && result['error_code'])
					cb(@getAPIException(result), result)
				else if (params['method'] == 'auth.expireSession' ||
						params['method'] == 'auth.revokeAuthorization') 
							@destroySession()

					cb(null, result)
			catch err
				cb(err, null)
	
			   
	isVideoPost: (path, method) ->
		method = method || 'GET'
		if (method == 'POST' && path.match(/^(\/)(.+)(\/)(videos)$/)) 
			return true
		else
			return false
	
 
	_graph: (path, method, params, cb) ->
		# allows for _graph(path, params, cb)
		if (_.isObject(method) && _.isFunction(params)) 
			cb = params
			params = method
			method = 'GET'
		else if(_.isFunction(method) && !params)
			cb = method
			method = 'GET'
			params = {}
		# Default values
		method = method || 'GET'
		params = params || {}
		 
		if(!_.isFunction(cb)) then throw new Error('Callback is required')	
		
		# Method override as we always do a POST
		params['method'] = method
		if (@isVideoPost(path, method)) 
			domainKey = 'graph_video'
		else 
			domainKey = 'graph'
		
		@_oauthRequest @getUrl(domainKey, path) ,params, (err, result) =>
			console.dir [err, result]
			try
				result = JSON.parse(result)
				#  results are returned, errors are thrown	
				if (_.isObject(result) && result['error']) 
					cb(@getAPIException(result), null)
				else
					cb(null, result)
			catch err
				cb(err, null)
			
	
	
	# Note: unlike the php-sdk, this function returns a parsed object when the content-type = 'application/json'
	# because I added a callback it messed up some of the logic here
	# this an ugly hack that can be removed but for now we're going with it
	_oauthRequest: (url, params, cb) ->
		hack = (params) =>
			options = {}
			# Stringify all values except instance of Restler.File
			for key, value of params
				if(!_.isString(value) &&  !(_.isObject(value) && value instanceof rest.File))
					params[key] = JSON.stringify(value)
				else if _.isObject(value) && value instanceof rest.File
					options.multipart = true
			
			@makeRequest(url, params,options, cb)
		
			 
		if (!params['access_token']) 
			@getAccessToken (err, access_token) -> 
				params['access_token'] = access_token
				hack(params)
		else
			hack(params)
	
	makeRequest: (url, params, options, cb) ->
		if !options then options = {multipart: false}
		options = _.extend(options, @REST_OPTIONS)
		options.data = params
		method = params['method'] && params['method'].toLowerCase() || 'post'
		delete params['method']
		
		if(method == 'get' && params && !_.isEmpty(params))
			if(_s.include(url,'?'))
				url += qs.stringify(params)
			else 
				url += "?" + qs.stringify(params)
		
		console.dir([url, method, params])
		
		# use => so we mess up our other callbacks
		rest[method](url, options).on('complete', (data, response) =>
			if(data instanceof Error) 
				cb(data, response)
				return
			if !data
				cb(new FacebookApiError({
					'error_code': 0,
					'error': {
						'message': 'Facebook API call returned no data',
						'type': 'RESTExcpetion'
					}
				}), null)
			else
				return cb(null, data)
		).on('error', (err) -> cb(err, null))
		
		
	
	   
			   
	parseSignedRequest: (signed_request) ->
		[encoded_sig, payload] = signed_request.split('.', 2)

		#  decode the data
		sig = @base64UrlDecode(encoded_sig)
		data = JSON.parse(@base64UrlDecode(payload))

		if (data['algorithm'].toUpper() != 'HMAC-SHA256') 
			@errorLog('Unknown algorithm. Expected HMAC-SHA256')
			return null
	    #  check sig			   
		expected_sig = crypto.createHash('sha256').update(payload).digest('binary')
		if (sig != expected_sig) 
			@errorLog('Bad Signed JSON signature!')
			return null

		return data
	
	getApiUrl: (method) ->
		READ_ONLY_CALLS = {
            'admin.getallocation' : 1,
            'admin.getappproperties' : 1,
            'admin.getbannedusers' : 1,
            'admin.getlivestreamvialink' : 1,
            'admin.getmetrics' : 1,
            'admin.getrestrictioninfo' : 1,
            'application.getpublicinfo' : 1,
            'auth.getapppublickey' : 1,
            'auth.getsession' : 1,
            'auth.getsignedpublicsessiondata' : 1,
            'comments.get' : 1,
            'connect.getunconnectedfriendscount' : 1,
            'dashboard.getactivity' : 1,
            'dashboard.getcount' : 1,
            'dashboard.getglobalnews' : 1,
            'dashboard.getnews' : 1,
            'dashboard.multigetcount' : 1,
            'dashboard.multigetnews' : 1,
            'data.getcookies' : 1,
            'events.get' : 1,
            'events.getmembers' : 1,
            'fbml.getcustomtags' : 1,
            'feed.getappfriendstories' : 1,
            'feed.getregisteredtemplatebundlebyid' : 1,
            'feed.getregisteredtemplatebundles' : 1,
            'fql.multiquery' : 1,
            'fql.query' : 1,
            'friends.arefriends' : 1,
            'friends.get' : 1,
            'friends.getappusers' : 1,
            'friends.getlists' : 1,
            'friends.getmutualfriends' : 1,
            'gifts.get' : 1,
            'groups.get' : 1,
            'groups.getmembers' : 1,
            'intl.gettranslations' : 1,
            'links.get' : 1,
            'notes.get' : 1,
            'notifications.get' : 1,
            'pages.getinfo' : 1,
            'pages.isadmin' : 1,
            'pages.isappadded' : 1,
            'pages.isfan' : 1,
            'permissions.checkavailableapiaccess' : 1,
            'permissions.checkgrantedapiaccess' : 1,
            'photos.get' : 1,
            'photos.getalbums' : 1,
            'photos.gettags' : 1,
            'profile.getinfo' : 1,
            'profile.getinfooptions' : 1,
            'stream.get' : 1,
            'stream.getcomments' : 1,
            'stream.getfilters' : 1,
            'users.getinfo' : 1,
            'users.getloggedinuser' : 1,
            'users.getstandardinfo' : 1,
            'users.hasapppermission' : 1,
            'users.isappuser' : 1,
            'users.isverified' : 1,
            'video.getuploadlimits' : 1
		}
		name = 'api'
		if (READ_ONLY_CALLS[method.toLowerCase()] == 1) 
			name = 'api_read'
		else if (method.toLowerCase() == 'video.upload')
			name = 'api_video'
		return @getUrl(name, 'restserver.php')
	
		
		
	getUrl: (name, path, params) ->
		path = path || ''
		params = params || {}
		url = @DOMAIN_MAP[name];
		if (path) 
			if (path[0] == '/') 
				path = path.substr(1)
		url += path
		if (params && !_.isEmpty(params)) 
			url += '?' + qs.stringify(params)
		return url
	
	
	getSignedRequest: () -> 
		if !@signedRequest
			if (@getRequestParameter('signed_request')) 
				@signedRequest = @parseSignedRequest(@getRequestParameter('signed_request'))
			else if (@getCookie(@getSignedRequestCookieName())) 
				@signedRequest = @parseSignedRequest(@getCookie(@getSignedRequestCookieName()))
		return @signedRequest
	
	 
	getCode: () ->
		req_code = @getRequestParameter('code')
		req_state = @getRequestParameter('state')
		if (req_code) 
			if (@state && req_state && @state == req_state) 
				#  CSRF state has done its job, so clear it
				@state = null
				@clearPersistentData('state')
				return req_code
		else 
			@errorLog('CSRF state token does not match one provided.');
		return false  
	

	# replace throwAPIException with getAPIException
	# in order to support callbacks		   
	getAPIException: (result) ->
		e = new FacebookApiException(result)
		switch e.getType() 
			#  OAuth 2.0 Draft 00 style, OAuth 2.0 Draft 10 style, REST server errors are just Exceptions
			when 'OAuthException', 'invalid_token', 'Exception'
				message = e.message
				if (_s.include(message, 'Error validating access token') ||
					_s.include(message,'Invalid OAuth access token') ||
 					_s.include(message,'An active access token must be used'))
					@destroySession()
		
		return e
	
	
	errorLog: (msg) ->
		console.dir(msg)
	
		
	base64UrlDecode: (input) ->
		search = /\-\_/g # -_
		replace = '+/'
		return new Buffer(input.replace(search,replace)).toString('base64')
	
	destroySession: () ->
		@accessToken = null
		@user = null
		@signedRequest = null
		@clearAllPersistentData()

		cookie_name = @getSignedRequestCookieName()
		# We can't remove the cookie from here because we have no reference
		# to any request so now the subclass has to implement a removeCookie function
		@removeCookie(cookie_name)
	   
	        #  The base domain is stored in the metadata cookie if not we fallback
		    #  to the current hostname (implemented by subclass)
		base_domain = '.' + @getHost()
		metadata = @getMetadataCookie()
		if (metadata['base_domain']) 
			base_domain = metadata['base_domain']
        
		# Implemented by subclass
		@setCookie(cookie_name, '', 0, '/', base_domain);
	
	getMetadataCookie: () ->
		cookie_name = @getMetadataCookieName()
		cookie_value = @getCookie(cookie_name)
		#  The cookie value can be wrapped in "-characters so remove them
		cookie_value = _s.trim(cookie_valie, '-')
		if !cookie_value then return {}
		parts = cookie_value.split('&')
		metadata = {}
		for part in parts 
			pair = part.split('=',2)
			metadata[decodeURIComponent(pair[0])] = if (pair.length > 1) then decodeURIComponent(pair[1]) else ''
		return metadata
	
	# "Abstract" functions
	setPersistentData: () -> throw FNI
	getPersistentData: () -> throw FNI
	clearPersistentData: () -> throw FNI
	clearAllPersistentData: () -> throw FNI 
	# Changed to abstract because without a reference to the request we can't do much
	getCurrentUrl: () -> throw FNI
	
	# These are unique to the node-facebook port
	setCookie: (name, value, expire, path, domain) -> throw FNI
	removeCookie: (name) -> throw FNI
	getCookie: (name) -> throw FNI
	getDomain: () -> throw FNI
	

module.exports = BaseFacebook



