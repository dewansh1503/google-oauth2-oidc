import express from 'express';
import cors from 'cors';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { createClient } from 'redis';

const app = express();
dotenv.config();
app.use(cors({ origin: 'http://localhost:4000', credentials: true }));
app.use(cookieParser());

const redisClient = createClient();
async function checkRedis() {
	try {
		await redisClient.connect();
		await redisClient.ping();
		console.log('Redis connected');
	} catch (err) {
		throw new apiError(503, `Redis: ${err.message}`);
	}
}
checkRedis();

const pool = new Pool({
	host: 'localhost',
	port: process.env.PSQL_PORT,
	user: process.env.PSQL_USER,
	password: process.env.PSQL_PASSWORD,
	database: process.env.PSQL_DATABASE,
	// error will be thrown after 10sec if not able to connect to db
	connectionTimeoutMillis: 7000,
});

async function checkDB() {
	try {
		const client = await pool.connect();
		console.log('PostgreSQL connected');
		client.release();
	} catch (err) {
		throw new apiError(503, `PostgreSQL ${err.message}`);
	}
}
checkDB();

function random(encoding = 'base64url', size = 32) {
	return crypto.randomBytes(size).toString(encoding);
}

const googleClient = new OAuth2Client(
	process.env.GOOGLE_CLIENT_ID,
	process.env.GOOGLE_CLIENT_SECRET,
	process.env.REDIRECT_URI,
);

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
		prompt: 'consent', // always show consent screen to user
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

	const userInfo = await userExists(payload.email, 'Google', payload.sub);
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
		userInfo.auth = await linkAuthAccount(userID, 'Google', payload.sub);
	} else if (!userInfo.auth) {
		// adding existing user's google account to auth_accounts psql
		userInfo.auth = await linkAuthAccount(userID, 'Google', payload.sub);
	}

	// creating session
	const sessionId = createSession(userID, req.headers['user-agent']);

	// generating access_token
	const accessToken = setAccessToken(userID, sessionId);

	// generating ref_token(hash) and storing it in psql
	const refreshToken = await setRefreshToken(userID);
});

app.listen(3000, () => {
	console.log('listening');
});
