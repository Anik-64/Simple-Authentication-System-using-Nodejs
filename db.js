require("dotenv").config();
const { Pool } = require("pg");

// PostgreSQL configuration for a local database
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT, 
});

// Test the database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error("Error acquiring client", err.stack);
    } else {
        console.log("Connected to PostgreSQL");
        client.query("SELECT NOW()", (err, result) => {
        release();
        if (err) {
            console.error("Error executing query", err.stack);
        } else {
            console.log("Current time from PostgreSQL:", result.rows[0].now);
        }
        });
    }
});

module.exports = pool;
