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

app.listen(3000, () => {
	console.log('listening');
});
