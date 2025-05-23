const database = require('../utils/database');

async function isAuthenticated(req, res, next) {
    // Check for session-based authentication first
    if (req.session && req.session.userId) {
        // User is authenticated via session
        return next();
    }

    // Check for token-based authentication
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7); // Remove 'Bearer ' prefix

        try {
            // Validate token and continue if valid
            const user = await database.getUserByToken(token);

            if (user) {
                // Add user to request object
                req.user = {
                    id: user.id,
                    username: user.username
                };
                return next();
            }

            // Token is invalid, redirect to login
            // Don't proceed further after redirect
            return res.redirect('/login');
        } catch (err) {
            console.error('Token authentication error:', err);
            // Don't proceed further after redirect
            return res.redirect('/login');
        }
    } else {
        // No authentication method available, redirect to login
        // Don't proceed further after redirect
        return res.redirect('/login');
    }
}

module.exports = {
    isAuthenticated
};
