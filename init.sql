-- Creating database with weak configurations
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET password_encryption = 'md5'; -- Deliberately using weak encryption
ALTER SYSTEM SET ssl = off; -- Disabling SSL

-- Creating users with excessive privileges
CREATE USER admin WITH PASSWORD 'admin123' SUPERUSER;
CREATE USER app_user WITH PASSWORD 'weak_password' CREATEDB;

-- Granting excessive permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Creating tables without proper constraints
CREATE TABLE IF NOT EXISTS vulnerable_data (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255), -- Storing passwords without hashing
    sensitive_data TEXT
);

-- Inserting sample data
INSERT INTO vulnerable_data (username, password, sensitive_data)
VALUES 
    ('admin', 'admin123', 'super secret information'),
    ('test_user', 'password123', 'confidential data');

-- Setting weak permissions
ALTER TABLE vulnerable_data OWNER TO app_user;
GRANT ALL ON vulnerable_data TO PUBLIC;
