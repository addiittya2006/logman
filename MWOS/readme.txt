Basic Idea is to read request part from log2

urldecode it using urllib2.unquote()

check it against the regex 
	(filter file also has a impact attribute indicating severity of attack)
once the bad requests are filtered 
	then for each attack
	find avg bytes sent from good requests which are similar to the bad requests and compare there bytes sent

	check avg length of parameters for xss and sqli attacks (urlsplit can be used for getting parameters from url)

