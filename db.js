const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

// Create database connection
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Initialize database
function initDatabase() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Create users table
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                points INTEGER DEFAULT 0,
                isAdmin BOOLEAN DEFAULT 0,
                isGuest BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )`);

            // Create challenges table
            db.run(`CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                flag TEXT NOT NULL,
                points INTEGER NOT NULL,
                category TEXT NOT NULL
            )`);

            // Create solved_challenges table (junction table for many-to-many relationship)
            db.run(`CREATE TABLE IF NOT EXISTS solved_challenges (
                user_id INTEGER NOT NULL,
                challenge_id INTEGER NOT NULL,
                solved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, challenge_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (challenge_id) REFERENCES challenges(id)
            )`);

            // Insert default challenges if they don't exist
            const defaultChallenges = [
                { id: 1, name: 'Hidden in Plain Sight', description: 'Check this simple webpage for hidden information. The flag is somewhere in the HTML.', flag: 'VUW{h1dd3n_1n_pl41n_s1ght}', points: 10, category: 'Web' },
                { id: 2, name: 'Base 64 Basics', description: 'Decode this Base64 string to find the flag: VlVXe0I0UzNfNjRfMXNfbjB0X2VuY3J5cHQxMG59', flag: 'VUW{B4S3_64_1s_n0t_encrypt10n}', points: 15, category: 'Crypto' },
                { id: 3, name: 'Digital Footprint', description: 'Find information about our club\'s GitHub repository that isn\'t on our website. What year was it created?', flag: 'VUW{2025}', points: 20, category: 'OSINT' },
                { id: 4, name: 'Hidden Message', description: 'Download this image and find the hidden message inside it. No special tools required, just careful observation.', flag: 'VUW{example_flag}', points: 25, category: 'Stego' }, //VUW{st3gn0_astly_h3r3_1_c0me}
                { id: 5, name: 'SQL Injection Basics', description: 'This simple login form is vulnerable to SQL injection. Can you bypass the authentication?', flag: 'VUW{sql_injection_basics}', points: 40, category: 'Web' },
                { id: 6, name: 'File Analysis', description: 'Download this file and use forensic tools to analyze its metadata and find hidden content.', flag: 'VUW{forensic_metadata}', points: 45, category: 'Forensics' },
                { id: 7, name: 'Caesar\'s Secret', description: 'Decode this Caesar cipher to find the flag: YZX{hJNnJa_lrynQa_rB_NJBh}', flag: 'VUW{caesar_cipher_is_easy}', points: 35, category: 'Crypto' },
                { id: 8, name: 'Simple Reversing', description: 'Download this simple program and analyze its code to find the password that reveals the flag.', flag: 'VUW{reverse_engineering_101}', points: 50, category: 'Reverse' },
                { id: 9, name: 'JWT Authentication Bypass', description: 'This web application uses JWT for authentication. Can you find a vulnerability in the implementation?', flag: 'VUW{jwt_alg_none}', points: 75, category: 'Web' },
                { id: 10, name: 'Buffer Overflow 101', description: 'Exploit this simple C program by overflowing its buffer to gain unauthorized access.', flag: 'VUW{buffer_overflow_detected}', points: 80, category: 'Binary' },
                { id: 11, name: 'RSA Fundamentals', description: 'You have the RSA public key and a ciphertext. Can you decrypt the message to find the flag?', flag: 'VUW{weak_rsa_params}', points: 85, category: 'Crypto' },
                { id: 12, name: 'Memory Analysis', description: 'Analyze this memory dump to find evidence of malicious activity and recover the flag.', flag: 'VUW{memory_forensics_master}', points: 90, category: 'Forensics' }
            ];

            defaultChallenges.forEach(challenge => {
                db.run(`INSERT OR IGNORE INTO challenges (id, name, description, flag, points, category) 
                        VALUES (?, ?, ?, ?, ?, ?)`,
                    [challenge.id, challenge.name, challenge.description, challenge.flag, challenge.points, challenge.category]);
            });

            // Create guest account if it doesn't exist
            db.get('SELECT COUNT(*) as count FROM users WHERE isGuest = 1', async (err, row) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                if (row.count === 0) {
                    try {
                        const hashedPassword = await bcrypt.hash('guest123', 10);
                        db.run(`INSERT INTO users (username, email, password, isGuest) 
                                VALUES (?, ?, ?, ?)`,
                            ['guest', 'guest@vuwctf.local', hashedPassword, 1],
                            (err) => {
                                if (err) {
                                    reject(err);
                                    return;
                                }
                                resolve();
                            });
                    } catch (error) {
                        reject(error);
                    }
                } else {
                    resolve();
                }
            });
        });
    });
}

// User functions
async function createUser(username, email, password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    return new Promise((resolve, reject) => {
        db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function(err) {
                if (err) reject(err);
                else resolve(this.lastID);
            });
    });
}

function getUserByUsername(username) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function getUserById(id) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function updateUserLastLogin(id) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [id], (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

// Additional user functions
function getUserByEmail(email) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function getUserRank(userId) {
    return new Promise((resolve, reject) => {
        db.get(`
            SELECT COUNT(*) + 1 as rank
            FROM users u1
            WHERE u1.points > (
                SELECT points
                FROM users u2
                WHERE u2.id = ?
            )
        `, [userId], (err, row) => {
            if (err) reject(err);
            else resolve(row.rank);
        });
    });
}

// Challenge functions
function getChallenges(page = 1, perPage = 10, categories = [], sortBy = 'points', sortOrder = 'ASC') {
    return new Promise((resolve, reject) => {
        let query = 'SELECT * FROM challenges';
        const params = [];
        
        // Add category filter if specified
        if (categories.length > 0) {
            query += ' WHERE category IN (' + categories.map(() => '?').join(',') + ')';
            params.push(...categories);
        }
        
        // Add sorting
        query += ` ORDER BY ${sortBy} ${sortOrder}`;
        
        // Add pagination
        const offset = (page - 1) * perPage;
        query += ' LIMIT ? OFFSET ?';
        params.push(perPage, offset);
        
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function getTotalChallenges(categories = []) {
    return new Promise((resolve, reject) => {
        let query = 'SELECT COUNT(*) as total FROM challenges';
        const params = [];
        
        if (categories.length > 0) {
            query += ' WHERE category IN (' + categories.map(() => '?').join(',') + ')';
            params.push(...categories);
        }
        
        db.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row.total);
        });
    });
}

function getAvailableCategories() {
    return new Promise((resolve, reject) => {
        db.all('SELECT DISTINCT category FROM challenges ORDER BY category', (err, rows) => {
            if (err) reject(err);
            else resolve(rows.map(row => row.category));
        });
    });
}

function getSolvedChallenges(userId) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT c.*, sc.solved_at 
                FROM challenges c 
                JOIN solved_challenges sc ON c.id = sc.challenge_id 
                WHERE sc.user_id = ?`, [userId], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function solveChallenge(userId, challengeId) {
    return new Promise((resolve, reject) => {
        db.run(`INSERT INTO solved_challenges (user_id, challenge_id) VALUES (?, ?)`,
            [userId, challengeId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

function updateUserPoints(userId, points) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET points = points + ? WHERE id = ?',
            [points, userId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

// Additional challenge functions
function getChallengeById(id) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM challenges WHERE id = ?', [id], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function isChallengeSolved(userId, challengeId) {
    return new Promise((resolve, reject) => {
        db.get(`
            SELECT COUNT(*) as count
            FROM solved_challenges
            WHERE user_id = ? AND challenge_id = ?
        `, [userId, challengeId], (err, row) => {
            if (err) reject(err);
            else resolve(row.count > 0);
        });
    });
}

// Additional user management functions
function getTotalUsers() {
    return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
            if (err) reject(err);
            else resolve(row.count);
        });
    });
}

function getAllUsers() {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM users', (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function updateUserInfo(userId, username, email) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET username = ?, email = ? WHERE id = ?',
            [username, email, userId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

async function updateUserPassword(userId, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, userId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

function deleteUser(userId) {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Delete solved challenges
            db.run('DELETE FROM solved_challenges WHERE user_id = ?', [userId]);
            
            // Delete user
            db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });
}

// Calculate user streak based on consecutive days of activity
function getUserStreak(userId) {
    return new Promise((resolve, reject) => {
        db.get(`
            WITH RECURSIVE dates AS (
                SELECT date(last_login) as login_date
                FROM users
                WHERE id = ?
                UNION ALL
                SELECT date(login_date, '-1 day')
                FROM dates
                WHERE login_date > date('now', '-30 days')
            ),
            logins AS (
                SELECT date(last_login) as login_date
                FROM users
                WHERE id = ?
                UNION
                SELECT date(solved_at) as login_date
                FROM solved_challenges
                WHERE user_id = ?
            )
            SELECT COUNT(*) as streak
            FROM dates d
            WHERE EXISTS (
                SELECT 1 FROM logins l
                WHERE l.login_date = d.login_date
            )
            AND d.login_date >= date('now', '-30 days')
            ORDER BY d.login_date DESC
            LIMIT 1
        `, [userId, userId, userId], (err, row) => {
            if (err) reject(err);
            else resolve(row ? row.streak : 0);
        });
    });
}

// User solve management
async function clearUserSolves(userId) {
    return new Promise((resolve, reject) => {
        db.run('DELETE FROM solved_challenges WHERE user_id = ?', [userId], (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

// Challenge management
function createChallenge(name, description, flag, points, category) {
    return new Promise((resolve, reject) => {
        db.run(`INSERT INTO challenges (name, description, flag, points, category) 
                VALUES (?, ?, ?, ?, ?)`,
            [name, description, flag, points, category],
            function(err) {
                if (err) reject(err);
                else resolve(this.lastID);
            });
    });
}

function updateChallenge(id, name, description, flag, points, category) {
    return new Promise((resolve, reject) => {
        db.run(`UPDATE challenges 
                SET name = ?, description = ?, flag = ?, points = ?, category = ?
                WHERE id = ?`,
            [name, description, flag, points, category, id],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

function deleteChallenge(id) {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Delete solved challenges first
            db.run('DELETE FROM solved_challenges WHERE challenge_id = ?', [id]);
            
            // Then delete the challenge
            db.run('DELETE FROM challenges WHERE id = ?', [id], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });
}

// System settings
function initSystemSettings() {
    return new Promise((resolve, reject) => {
        db.run(`CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            site_name TEXT DEFAULT 'VUW CTF',
            maintenance_mode BOOLEAN DEFAULT 0,
            registration_enabled BOOLEAN DEFAULT 1,
            max_points_per_day INTEGER DEFAULT 1000,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) {
                reject(err);
                return;
            }
            
            // Insert default settings if they don't exist
            db.run(`INSERT OR IGNORE INTO system_settings (id) VALUES (1)`, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });
}

function getSystemSettings() {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM system_settings WHERE id = 1', (err, row) => {
            if (err) reject(err);
            else resolve(row || {
                site_name: 'VUW CTF',
                maintenance_mode: false,
                registration_enabled: true,
                max_points_per_day: 1000
            });
        });
    });
}

function updateSystemSettings(settings) {
    return new Promise((resolve, reject) => {
        db.run(`UPDATE system_settings 
                SET site_name = ?,
                    maintenance_mode = ?,
                    registration_enabled = ?,
                    max_points_per_day = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1`,
            [settings.siteName, settings.maintenanceMode, settings.registrationEnabled, settings.maxPointsPerDay],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

function updateUserAdminStatus(userId, isAdmin) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET isAdmin = ? WHERE id = ?',
            [isAdmin ? 1 : 0, userId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

async function createFirstAdmin() {
    return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as count FROM users', async (err, row) => {
            if (err) {
                reject(err);
                return;
            }
            
            if (row.count === 0) {
                try {
                    const adminId = await createUser('vuwctf', 'vuwctf@gmail.com', 'zoU!nQxe6N');
                    await updateUserAdminStatus(adminId, true);
                    resolve(true);
                } catch (error) {
                    reject(error);
                }
            } else {
                resolve(false);
            }
        });
    });
}

// User challenge management
function addUserChallenge(userId, challengeId) {
    return new Promise((resolve, reject) => {
        db.run(`INSERT OR IGNORE INTO solved_challenges (user_id, challenge_id) VALUES (?, ?)`,
            [userId, challengeId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

function removeUserChallenge(userId, challengeId) {
    return new Promise((resolve, reject) => {
        db.run(`DELETE FROM solved_challenges WHERE user_id = ? AND challenge_id = ?`,
            [userId, challengeId],
            (err) => {
                if (err) reject(err);
                else resolve();
            });
    });
}

// Guest user functions
async function createGuestUser() {
    const guestUsername = `guest_${Math.random().toString(36).substring(2, 8)}`;
    const guestEmail = `${guestUsername}@guest.local`;
    const guestPassword = Math.random().toString(36).substring(2, 12);
    
    try {
        const userId = await createUser(guestUsername, guestEmail, guestPassword);
        return {
            id: userId,
            username: guestUsername,
            email: guestEmail,
            password: guestPassword,
            isGuest: true
        };
    } catch (error) {
        console.error('Error creating guest user:', error);
        throw error;
    }
}

// Verify guest user status
function verifyGuestUser() {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ? AND isGuest = 1', ['guest'], (err, row) => {
            if (err) {
                reject(err);
                return;
            }
            if (!row) {
                // If guest user doesn't exist or isn't marked as guest, recreate it
                bcrypt.hash('guest123', 10).then(hashedPassword => {
                    db.run(`INSERT OR REPLACE INTO users (username, email, password, isGuest) 
                            VALUES (?, ?, ?, ?)`,
                        ['guest', 'guest@vuwctf.local', hashedPassword, 1],
                        (err) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            resolve(true);
                        });
                }).catch(reject);
            } else {
                resolve(false);
            }
        });
    });
}

// Update exports
module.exports = {
    initDatabase,
    createUser,
    getUserByUsername,
    getUserByEmail,
    getUserById,
    getUserRank,
    getTotalUsers,
    getAllUsers,
    updateUserInfo,
    updateUserPassword,
    updateUserLastLogin,
    updateUserAdminStatus,
    deleteUser,
    createFirstAdmin,
    getChallenges,
    getChallengeById,
    getSolvedChallenges,
    isChallengeSolved,
    solveChallenge,
    updateUserPoints,
    getUserStreak,
    getTotalChallenges,
    getAvailableCategories,
    clearUserSolves,
    createChallenge,
    updateChallenge,
    deleteChallenge,
    initSystemSettings,
    getSystemSettings,
    updateSystemSettings,
    addUserChallenge,
    removeUserChallenge,
    createGuestUser,
    verifyGuestUser
};