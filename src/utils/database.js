const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.resolve(__dirname, '../../database/database.sqlite');
let db = null;

// Ensure database directory exists
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize database tables
const initialize = function (database) {
    database.serialize(() => {
        // Create users table
        database.run(`CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            pass_matrix TEXT,
            token TEXT
        )`, (err) => {
            if (err) console.error('Error creating user table:', err.message);
        });

        // Create iot table
        database.run(`CREATE TABLE IF NOT EXISTS iot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device TEXT UNIQUE NOT NULL,
            type TEXT,
            public_key TEXT,
            dmidecode_hash TEXT,
            lscpu_hash TEXT,
            MAC TEXT,
            gps TEXT,
            status TEXT,
            last_auth_time TIMESTAMP,
            challenge TEXT
        )`, (err) => {
            if (err) console.error('Error creating iot table:', err.message);
        });

        // Create manage table
        database.run(`CREATE TABLE IF NOT EXISTS manage (
            device TEXT NOT NULL,
            temperature REAL,
            humidity REAL,
            weather TEXT,
            update_time TIMESTAMP NOT NULL,
            PRIMARY KEY (device, update_time),
            FOREIGN KEY (device) REFERENCES iot(device)
        )`, (err) => {
            if (err) console.error('Error creating manage table:', err.message);
        });
    });

    return database;
};

// Get a database connection
const getDb = () => {
    if (!db) {
        db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('Error connecting to database:', err.message);
                throw err;
            }
            console.log('Connected to SQLite database at', dbPath);
            initialize(db);
        });
    }
    return db;
};

// Promise-based connection (useful for async startup)
const connect = function () {
    return new Promise((resolve, reject) => {
        try {
            const database = getDb();
            resolve(database);
        } catch (err) {
            reject(err);
        }
    });
};

// Execute queries that don't return data
const executeQuery = (query, params = []) => {
    return new Promise((resolve, reject) => {
        const database = getDb();
        database.run(query, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
};

// Execute queries that return data
const fetchQuery = (query, params = []) => {
    return new Promise((resolve, reject) => {
        const database = getDb();
        database.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

// Close database connection
const close = function () {
    if (db) {
        db.close((err) => {
            if (err) console.error('Error closing database:', err.message);
            else {
                console.log('Database connection closed');
                db = null;
            }
        });
    }
};

// User operations
const getUserByUsername = async (username) => {
    try {
        const rows = await fetchQuery('SELECT * FROM user WHERE username = ?', [username]);
        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error('Error getting user by username:', error);
        throw error;
    }
};

const createUser = async (username, password) => {
    try {
        const result = await executeQuery(
            'INSERT INTO user (username, password) VALUES (?, ?)',
            [username, password]
        );
        return { id: result.lastID, username };
    } catch (error) {
        console.error('Error creating user:', error);
        throw error;
    }
};

const updateUserToken = async (userId, token) => {
    try {
        await executeQuery(
            'UPDATE user SET token = ? WHERE id = ?',
            [token, userId]
        );
        return true;
    } catch (error) {
        console.error('Error updating user token:', error);
        throw error;
    }
};


const getUserByToken = async (token) => {
    try {
        const rows = await fetchQuery('SELECT * FROM user WHERE token = ?', [token]);
        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error('Error getting user by token:', error);
        throw error;
    }
};

module.exports = {
    connect,
    getDb,
    initialize,
    executeQuery,
    fetchQuery,
    getUserByUsername,
    createUser,
    updateUserToken,
    getUserByToken,
    close
};
