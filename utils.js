class apiError extends Error {
	constructor(statusCode = 500, message = 'Samasyaa!!', success = false) {
		super(message);
		this.statusCode = statusCode;
		this.success = success;
	}
}

function errorhandler(err, req, res, next) {
	console.log(err.message.toUpperCase());
	console.log('STACK :>> ', err.stack);
	res.status(err.statusCode || 500).json({
		message: err.message.toUpperCase(),
		success: err.success,
	});
}
