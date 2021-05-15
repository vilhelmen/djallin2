# TODO:

1. Figure out how everything works
	- how does this even boot I feel like I'm taking crazy pills
1. Port auth system from judge to me.
	- client id r50bzaj62mdvoo3nojyfuqeewxlj23
	- https://id.twitch.tv/oauth2/authorize?response_type=token&client_id=r50bzaj62mdvoo3nojyfuqeewxlj23&redirect_uri=http://localhost:42069&scope=channel:read:redemptions+chat:read
		- research state value, something about replay attacks? 'state=tQlBKW4OEJSn3SQ'
	- Oh yeah this also is a user access token
	- chat:read+channel:read:redemptions???? I think redepmtions are fed into the chat stream, so channel could be skipped
	- local webserver to capture token? Check if auth needs to be redone. Token renewals? why is vmware running at https://localhost
	- External site to parrot auth token back at users? I mean, I trust me. But, ya know, I get it.
1. Modernize??
	- Lol audio looks absolutely fucked in python, so playsound may be best unless I make everyone convert to wav
	- Or require a whole game framework lmao
1. Rewrite
	- I... know a lot of python

1. Build system for windows.


## Plans:
1. TOML config - Listen, they say this is the best
	- Lol I have a website that presents config to the user as yaml but reads and stores it as json
	- The site itself is configured with yaml

1. lamo why you gotta run as admin in windows

1. Config blocks/sound channels/whatever
	- an entry per point reward or chat message response
		- type (chat, reward str, etc)
		- target (audio dir or speciffic file)
			- abs or rel? rel to config location? Path(conf).abssolute.parent / conf[x].target ?
		- some light queue controls - queue hopping? (can you hop a queue?? am I gonna have to use a list lol)
		- ...special mode for my special boy. This may have to be a site-wide setting.
	- keep... statistics? could be fun.
	- hook system for custom stuff. but how???? msg response with a code block???????????????? big yikes.
		- TBH a handful of these usages could be handled by lioranboard

1. I mean, we could have it redirect a local 404 to a server for discovery. Idk. Remote... playback? That's not a thing.



