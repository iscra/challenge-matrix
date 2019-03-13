# matrix-challenge

The pill you took is part of a trace program. It's designed to disrupt your input/output carrier signal so we can pinpoint your location.

But it's not perfect and only allows us to narrow it down to the sector you're at. To delve even deeper, we use other sources of data: sentinels, sniffers, loopholes. The only drawback is that they produce a different output which we cannot work with. Keep in mind, Neo, our terminals are old and highly unreliable, failures happen.

Tank and Cypher are doing their best, but we need your hacking skills to parse the data and get it into our system. The interface definitions can be found down below.

Our operators in Zion are awaiting, please use your own Github terminal to send the message out.

		[GET ] /routes to get whatever we already collected.
		parameter	format	value
		passphrase	fasten your seat belt Dorothy	XXXXXXXXXXXXXXXXXXXXXXX
		source	alphanumeric code	sentinels, sniffers, loopholes

		[POST] /routes to import the parsed data into our system.
		parameter	description	value/format
		passphrase	fasten your seat belt Dorothy	XXXXXXXXXXXXXXXXXXXXXXX
		source	alphanumeric code	sentinels, sniffers, loopholes
		start_node	alphanumeric code	alpha, beta, gamma, delta, theta, lambda, tau, psi, omega
		end_node	alphanumeric code	alpha, beta, gamma, delta, theta, lambda, tau, psi, omega
		start_time	ISO 8601 UTC time	YYYY-MM-DDThh:mm:ss
		end_time	ISO 8601 UTC time	YYYY-MM-DDThh:mm:ss

The machines are close. Hurry up, Neo.
