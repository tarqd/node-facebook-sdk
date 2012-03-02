
/*
 * GET home page.
 */

exports.index = function(req, res){
  console.dir('yo ' + req.facebook)
  req.facebook.getUser(function(err, uid){
		if(uid == 0){
			res.redirect(req.facebook.getLoginUrl())
		}
		else{
			res.render('index', {title: 'Yo', body: "Hello " + req.facebook.me.first_name + "!"})
		}
  })
  //res.render('index', { title: 'Express', body: 'HI' })
};
