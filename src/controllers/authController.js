class AuthController {
    constructor(database) {
        this.database = database;
    }

    async registerUser(req, res) {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        try {
            const existingUser = await this.database.getUserByUsername(username);
            if (existingUser) {
                return res.status(400).json({ message: 'Username already exists.' });
            }

            const newUser = await this.database.createUser(username, password);
            return res.status(201).json({
                message: 'User registered successfully.',
                success: true,
                user: newUser
            });
        } catch (error) {
            return res.status(500).json({ message: 'Error registering user.', error });
        }
    }

    async loginUser(req, res) {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        try {
            const user = await this.database.getUserByUsername(username);
            if (!user || user.password !== password) {
                return res.status(401).json({ message: 'Invalid username or password.' });
            }

            // Check if user has a pass_matrix, if not they need to set one up
            if (!user.pass_matrix) {
                return res.status(200).json({
                    message: 'First-time login, please set your pass matrix.',
                    needPassMatrix: true,
                    user: {
                        id: user.id,
                        username: user.username
                    }
                });
            }

            // Return success but require pass matrix verification
            return res.status(200).json({
                message: 'Initial login successful, please enter your pass matrix.',
                success: true,
                requirePassMatrix: true,
                passMatrixLength: user.pass_matrix.length,
                passMatrix: this.generatePassMatrixString(user.pass_matrix),
                user: {
                    id: user.id,
                    username: user.username
                }
            });
        } catch (error) {
            return res.status(500).json({ message: 'Error logging in.', error });
        }
    }

    generatePassMatrixString(passMatrix) {
        const totalLength = 16 * passMatrix.length;
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>? ';
        let result = '';

        for (let blockIndex = 0; blockIndex < passMatrix.length; blockIndex++) {
            // Generate a 16-character block
            let block = '';

            // Choose a random position (0-15) for the pass matrix character
            const passMatrixPosition = Math.floor(Math.random() * 16);

            for (let i = 0; i < 16; i++) {
                if (i === passMatrixPosition) {
                    // Insert the pass matrix character at the random position
                    block += passMatrix[blockIndex];
                } else {
                    // Fill other positions with random characters
                    const randomIndex = Math.floor(Math.random() * characters.length);
                    block += characters[randomIndex];
                }
            }

            result += block;
        }

        return result;
    }

    async setPassMatrix(req, res) {
        const { username, passMatrix } = req.body;

        if (!username || !passMatrix) {
            return res.status(400).json({ message: 'Username and pass matrix are required.' });
        }

        try {
            await this.database.executeQuery(
                'UPDATE user SET pass_matrix = ? WHERE username = ?',
                [passMatrix, username]
            );

            return res.status(200).json({
                message: 'Pass matrix set successfully.',
                success: true
            });
        } catch (error) {
            return res.status(500).json({ message: 'Error setting pass matrix.', error });
        }
    }

    async verifyPassMatrix(req, res) {
        const { username, passMatrix } = req.body;

        if (!username || !passMatrix) {
            return res.status(400).json({ message: 'Username and pass matrix are required.' });
        }

        try {
            const user = await this.database.getUserByUsername(username);

            if (!user || user.pass_matrix !== passMatrix) {
                return res.status(401).json({ message: 'Invalid pass matrix.' });
            }

            // Store user information in session after full authentication
            req.session.userId = user.id;
            req.session.username = user.username;

            return res.status(200).json({
                message: 'Authentication successful.',
                success: true,
                user: {
                    id: user.id,
                    username: user.username
                }
            });
        } catch (error) {
            return res.status(500).json({ message: 'Error verifying pass matrix.', error });
        }
    }

    async generateToken(req, res) {
        try {
            const { userId } = req.body;

            if (!userId) {
                return res.status(400).json({ message: 'User ID is required.' });
            }

            // Generate a random token
            const crypto = require('crypto');
            const token = crypto.randomBytes(32).toString('hex');

            // Save token to database
            await this.database.updateUserToken(userId, token);

            return res.status(200).json({
                message: 'Token generated successfully.',
                success: true,
                token: token
            });
        } catch (error) {
            return res.status(500).json({ message: 'Error generating token.', error });
        }
    }

    async validateToken(req, res) {
        try {
            const { token } = req.body;

            if (!token) {
                return res.status(400).json({ message: 'Token is required.' });
            }

            const user = await this.database.getUserByToken(token);

            if (!user) {
                return res.status(401).json({ message: 'Invalid token.' });
            }

            return res.status(200).json({
                message: 'Token is valid.',
                success: true,
                user: {
                    id: user.id,
                    username: user.username
                }
            });
        } catch (error) {
            return res.status(500).json({ message: 'Error validating token.', error });
        }
    }
}

module.exports = AuthController;
