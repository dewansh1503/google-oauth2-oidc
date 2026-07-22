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

app.listen(3000, () => {
	console.log('listening');
});
