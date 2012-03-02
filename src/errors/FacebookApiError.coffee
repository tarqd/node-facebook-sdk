class FacebookApiError extends Error
	constructor: (@result) ->
		@code = result['error_code'] || 0
		msg = "Unknown Error. Check getResult()"
		
		if result['error_description']
			msg = result['error_description']
		else if result['error'] && typeof(result['error']) == 'array'
			msg = result['error']['message']
			@type = result['error']['type']
		else if result['error_msg']
			msg = result['error_msg']
			
		if typeof(result['error']) == 'string'
			@type = result['error']
		
		voidSession =[]
		
		super msg
		
	getResult: -> @result
	
	getType: ->  @type || 'Exception'
	
	toString: ->  "#{@type}:#{@code}:#{message}"
	
	
	
module.export = FacebookApiError
	
	
	
	
		
		

			