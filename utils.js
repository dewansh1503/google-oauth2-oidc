class apiError extends Error {
	constructor(statusCode = 500, message = 'Samasyaa!!', success = false) {
		super(message);
		this.statusCode = statusCode;
		this.success = success;
	}
}
