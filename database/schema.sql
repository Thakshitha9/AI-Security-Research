-- Optional history database for the AI Security Research Platform.
-- The APIs also create these tables when they can connect.
-- Create the database and user in MySQL, then run this script.

CREATE DATABASE IF NOT EXISTS ai_security_platform
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE ai_security_platform;

CREATE TABLE IF NOT EXISTS phishing_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    risk_score INT NOT NULL,
    indicators TEXT,
    ai_explanation MEDIUMTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    module VARCHAR(64) NOT NULL,
    target VARCHAR(512) NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    risk_score INT NULL,
    finding TEXT,
    evidence TEXT,
    explanation MEDIUMTEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
