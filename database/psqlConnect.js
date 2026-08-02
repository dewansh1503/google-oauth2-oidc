import { Pool } from 'pg';
import { apiError } from '../utils.js';
import { configDotenv } from 'dotenv';

const pool = new Pool({
	host: 'localhost',
	port: process.env.PSQL_PORT,
	user: process.env.PSQL_USER,
	password: process.env.PSQL_PASSWORD,
	database: process.env.PSQL_DATABASE,
	// error will be thrown after 10sec if not able to connect to db
	connectionTimeoutMillis: 7000,
});

async function checkDB(pool) {
	try {
		const client = await pool.connect();
		console.log('PostgreSQL connected');
		client.release();
	} catch (err) {
		throw new apiError(503, `POSTGRESQL ${err.message}`);
	}
}
await checkDB(pool);
export { pool };
