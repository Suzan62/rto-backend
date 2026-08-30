const mysql = require('mysql2/promise');
require('dotenv').config();

async function runQueries() {
  try {
    const connection = await mysql.createConnection({
      uri: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });

    console.log("Connecting to Aiven MySQL...");

    await connection.query(`
      CREATE TABLE IF NOT EXISTS dealers (
        dealer_id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        default_rate DECIMAL(10, 2) DEFAULT 1500.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(20) DEFAULT 'ADMIN',
        dealer_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (dealer_id) REFERENCES dealers(dealer_id) ON DELETE SET NULL
      );
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS cases (
        case_id INT AUTO_INCREMENT PRIMARY KEY,
        dealer_id INT NOT NULL,
        vehicle_no VARCHAR(20) NOT NULL,
        customer_name VARCHAR(100) NOT NULL,
        service_type VARCHAR(100) NOT NULL,
        govt_fee DECIMAL(10, 2) DEFAULT 0.00,
        agent_fee DECIMAL(10, 2) DEFAULT 1500.00,
        status VARCHAR(50) DEFAULT 'NEW_CASES',
        error_reason TEXT NULL,
        rc_file_url TEXT NULL,
        is_billed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (dealer_id) REFERENCES dealers(dealer_id) ON DELETE CASCADE
      );
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS dealer_payments (
        payment_id INT AUTO_INCREMENT PRIMARY KEY,
        dealer_id INT NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        payment_mode VARCHAR(30) DEFAULT 'CASH',
        notes TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (dealer_id) REFERENCES dealers(dealer_id) ON DELETE CASCADE
      );
    `);

    await connection.query(`
      INSERT IGNORE INTO users (username, password_hash, role)
      VALUES ('admin', 'admin123', 'ADMIN');
    `);

    console.log("Tables and Admin user created successfully in Aiven MySQL!");
    await connection.end();
    process.exit(0);
  } catch (err) {
    console.error("Failed to run queries:", err.message);
    process.exit(1);
  }
}

runQueries();