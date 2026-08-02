import { createClient } from 'redis';
import { apiError } from '../utils.js';

const redisClient = createClient();
async function checkRedis(redisClient) {
	try {
		await redisClient.connect();
		await redisClient.ping();
		console.log('Redis connected');
	} catch (err) {
		throw new apiError(503, `REDIS: ${err.message}`);
	}
}
await checkRedis(redisClient);
export { redisClient };
