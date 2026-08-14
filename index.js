import express from 'express';
import cors from 'cors';
import { OAuth2Client } from 'google-auth-library';
import { apiError, errorhandler } from './utils.js';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { redisClient } from './database/redisConnect.js';
import { pool } from './database/psqlConnect.js';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';

const app = express();
dotenv.config();
app.use(cors({ origin: 'http://localhost:4000', credentials: true }));
app.use(cookieParser());

function random(encoding = 'base64url', size = 32) {
	return crypto.randomBytes(size).toString(encoding);
}

async function revokeRefreshToken(user_id, token) {
	const tokenHash = crypto
		.createHash('sha256', process.env.TOKEN_PEPPER)
		.update(token)
		.digest('base64url');
	const result = await pool.query(
		`update refresh_tokens set revoked = true where user_id=$1 and token_hash=$2`,
		[user_id, tokenHash],
	);
	if (!result.rowCount) {
		throw new apiError(404, 'Invalid refresh token');
	}
}

async function revokeSession(session_id) {
	const res = await redisClient.hGetDel(`session:${session_id}`);
	console.log('deleted session', res);
}

async function rotateRefreshToken(refresh_token) {
	const isTokenValid = await verifyRefreshToken(refresh_token);
	const { sid: session_id } = jwt.decode(refresh_token);
	await revokeSession(session_id);
	if (!isTokenValid) {
		throw new apiError(400, 'Token invalid or expired');
	}
	const { sub: user_id, token } = jwt.decode(refresh_token);
	await revokeRefreshToken(user_id, token);
	const new_refresh_token = await setRefreshToken(user_id);
	return new_refresh_token;
}

async function verifyAccessToken(access_token) {
	try {
		const { sid: sessionId, sub: userId } = jwt.verify(
			access_token,
			process.env.ACCESS_TOKEN_SECRET,
		);
		const session = await redisClient.hGetAll(`session:${sessionId}`);
		if (!session.session_id || !session.user_id) {
			return false;
		}

		const key = `user:${session.user_id}:sessions`;
		const value = `${session.session_id}`;
		// session belongs to the user
		const exists = await redisClient.sIsMember(key, value);
		if (!exists) {
			return false;
		}

		// valid access token
		return true;
	} catch (err) {
		return false;
	}
}

async function verifyRefreshToken(refresh_token) {
	try {
		const { token, sub: user_id } = jwt.verify(
			refresh_token,
			process.env.REFRESH_TOKEN_SECRET,
		);

		const tokenHash = crypto
			.createHash('sha256', process.env.TOKEN_PEPPER)
			.update(token)
			.digest('base64url');

		const result = await pool.query(
			'select * from refresh_tokens where user_id=$1 and token_hash=$2;',
			[user_id, tokenHash],
		);
		if (!result.rowCount) {
			return false;
		}
		const expiry = result.rows[0].expires_at;
		const revoked = result.rows[0].revoked;

		if (revoked || isAfter(new Date(), new Date(expiry))) {
			return false;
		}
		// token is valid
		return true;
	} catch (err) {
		return false;
	}
}

async function setRefreshToken(user_id, session_id) {
	const token = crypto.randomBytes(32).toString('base64url');
	const refreshToken = jwt.sign(
		{
			sub: user_id,
			token,
		},
		process.env.REFRESH_TOKEN_SECRET,
		{
			expiresIn: `${process.env.REFRESH_TOKEN_EXPIRY}d`,
			algorithm: 'HS256',
			audience: 'http://localhost:3000',
			issuer: 'http://localhost:3000',
		},
	);
	const refreshTokenHash = crypto
		.createHash('sha256', process.env.TOKEN_PEPPER)
		.update(token)
		.digest('base64url');

	const expiry = addDays(
		new Date(),
		parseInt(process.env.REFRESH_TOKEN_EXPIRY),
	);
	const result = await pool.query(
		'insert into refresh_tokens (id, user_id, token_hash, expires_at) values ($1,$2,$3,$4);',
		[crypto.randomUUID(), user_id, refreshTokenHash, expiry.toISOString()],
	);
	return refreshToken;
}

function setAccessToken(user_id, session_id) {
	const access_token = jwt.sign(
		{
			sub: user_id,
			sid: session_id,
		},
		process.env.ACCESS_TOKEN_SECRET,
		{
			expiresIn: `${process.env.ACCESS_TOKEN_EXPIRY}d`,
			algorithm: 'HS256',
			audience: 'http://localhost:3000',
			issuer: 'http://localhost:3000',
		},
	);
	return access_token;
}

async function userExistsInPSQL(email, provider, provider_id) {
	const user = await pool.query('select * from users where email=$1', [
		email,
	]);
	let userInfo = { user: false, auth: false };
	if (user.rows[0]) {
		userInfo.user = user.rows[0];
		// check if login method exists
		const auth = await pool.query(
			'select * from auth_accounts where user_id=$1 and provider=$2 and provider_id=$3',
			[user.rows[0].id, provider, provider_id],
		);
		if (auth.rows[0]) {
			userInfo.auth = auth.rows[0];
		}
	}
	return userInfo;
}

async function linkAuthAccount(user_id, provider, provider_id) {
	const auth = await pool.query(
		'insert into auth_accounts ( id, user_id, provider, provider_id) values ($1,$2,$3,$4);',
		[crypto.randomUUID(), user_id, provider, provider_id],
	);
	return auth.rows[0];
}

const googleClient = new OAuth2Client(
	process.env.GOOGLE_CLIENT_ID,
	process.env.GOOGLE_CLIENT_SECRET,
	process.env.REDIRECT_URI,
);

function getDeviceInfo(userAgent) {
	const parser = new UAParser(userAgent);
	const deviceInfo = {
		BrowserName: parser.getBrowser(),
		OSName: parser.getOS(),
		DeviceType: parser.getDevice(),
	};
	return deviceInfo;
}

const authLimiter = rateLimit({
	windowMs: 60 * 1000, // sixty seconds
	limit: 20,
	keyGenerator: (req) => {
		return ipKeyGenerator(req.ip);
	},
	handler: (req, res) => {
		res.status(429).json({
			message: 'Too many login attempts. Try again later.',
		});
	},
});

async function findAndVerifyTokens(req, res, next) {
	const access_token = req.cookies?.accessToken;
	if (access_token && (await verifyAccessToken(access_token))) {
		// verify access token if valid the return else go ahead
		return next(new apiError(403, 'User is already loggedin'));
	}

	const refresh_token = req.cookies?.refreshToken;
	if (refresh_token && (await verifyRefreshToken(refresh_token))) {
		return next(new apiError(403, 'User is already loggedin'));
	}
	next();
}

app.get('/api/auth/google', async (req, res) => {
	const code_verifier = random();
	const codeChallenge = crypto
		.createHash('sha256')
		.update(code_verifier)
		.digest('base64url');

	const state = random('hex');
	const nonce = random('hex');

	const url = googleClient.generateAuthUrl({
		access_type: 'offline', // for getting refresh token
		scope: ['openid', 'email', 'profile'],
		// prompt: 'consent', // always show consent screen to user
		state,
		nonce,
		code_challenge: codeChallenge,
		code_challenge_method: 'S256',
	});

	// pushing [state, nonce, code_verifier] to redis
	await redisClient.set(
		`state:${state}`,
		JSON.stringify({ nonce, code_verifier }),
		{
			expiration: {
				type: 'EX',
				value: 300, // sec (5 min)
			},
		},
	);

	res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res, next) => {
	try {
		const code = req.query.code;
		const state = req.query.state;
		if (!code) {
			throw new apiError(400, 'Access denied by user');
		}
		if (!state) {
			throw new apiError(403, 'Unauthorized access missing state');
		}

		const storedData = await redisClient.getDel(`state:${state}`);
		if (!storedData) {
			throw new apiError(403, 'Invalid or missing state');
		}

		const storedDataJson = JSON.parse(storedData);
		const { tokens } = await googleClient.getToken({
			code,
			codeVerifier: storedDataJson.code_verifier,
		});

		const ticket = await googleClient.verifyIdToken({
			idToken: tokens.id_token,
			audience: process.env.GOOGLE_CLIENT_ID,
		});
		const payload = ticket.getPayload();
		if (payload.nonce !== storedDataJson.nonce) {
			throw new apiError(404, 'Invalid token nonce missing');
		}

		const userInfo = await userExistsInPSQL(
			payload.email,
			'Google',
			payload.sub,
		);
		// check if the user is new then only issue new userID
		let userID = userInfo.user.id;
		if (!userInfo.user) {
			// creating user
			userID = crypto.randomUUID();
			await pool.query(
				'insert into users (id, email, name, avatar_url) values ($1,$2,$3,$4);',
				[userID, payload.email, payload.name, payload.picture],
			);

			// adding user's google account to auth_accounts psql
			userInfo.auth = await linkAuthAccount(
				userID,
				'Google',
				payload.sub,
			);
		} else if (!userInfo.auth) {
			// adding existing user's google account to auth_accounts psql
			userInfo.auth = await linkAuthAccount(
				userID,
				'Google',
				payload.sub,
			);
		}

		// creating session
		const sessionId = await createSession(
			userID,
			req.headers['user-agent'],
		);

		// generating access_token
		const accessToken = setAccessToken(userID, sessionId);

		// generating ref_token(hash) and storing it in psql
		const refreshToken = await setRefreshToken(userID);

		const options = {
			httpOnly: true,
			sameSite: 'lax',
			secure: true,
		};
		res.cookie('accessToken', accessToken, {
			...options,
			expires: addDays(new Date(), process.env.ACCESS_TOKEN_EXPIRY),
		});
		res.cookie('refreshToken', refreshToken, {
			...options,
			expires: addDays(new Date(), process.env.REFRESH_TOKEN_EXPIRY),
		});
		res.redirect('http://localhost:4000');
	} catch (error) {
		next(error);
	}
});

app.get('/api/me', (req, res) => {
	const { accessToken } = req.cookies;
	try {
		if (!accessToken) {
			return res.send({ message: 'no token' });
		}

		const resp = jwt.verify(
			req.cookies.accessToken,
			process.env.ACCESS_TOKEN_SECRET,
		);
		res.json({ expired: false, user_id: resp.sub });
	} catch (error) {
		res.json({ expired: error.message });
	}
});

app.use(errorhandler);

app.listen(3000, () => {
	console.log('listening');
});
