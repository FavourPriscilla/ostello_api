/**
 * controllers/authController.js – Authentication Controller (Ostello)
 */

const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const dotenv = require('dotenv');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/email');

dotenv.config();

/**
 * POST /api/register
 * Registers a new user with email verification
 */
const register = async (req, res) => {
    const { full_name, email, phone, password, role, institution } = req.body;

    // Validate required fields
    if (!full_name || !email || !password) {
        return res.status(400).json({ error: 'full_name, email, and password are required.' });
    }

    // Validate role
    const validRoles = ['STUDENT', 'CUSTODIAN'];
    const userRole = role ? role.toUpperCase() : 'STUDENT';
    if (!validRoles.includes(userRole)) {
        return res.status(400).json({ error: 'Role must be STUDENT or CUSTODIAN.' });
    }

    try {
        // Hash the password before storing
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate verification token
        const verification_token = uuidv4();

        // Create user in database
        await User.create({
            full_name,
            email,
            phone,
            password: hashedPassword, // Pass hashed password
            role: userRole,
            institution,
            verification_token,
        });

        // Send verification email
        await sendVerificationEmail(email, verification_token);

        res.status(201).json({
            message: 'Registration successful! Please check your email to verify your account.',
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email already in use.' });
        }
        res.status(500).json({ error: err.message });
    }
};

/**
 * POST /api/login
 * Authenticates a user and returns a JWT token
 */
const login = async (req, res) => {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // Find user by email
        const [results] = await User.findByEmail(email);
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const user = results[0];

        // Check if email is verified
        if (!user.is_verified) {
            return res.status(403).json({ error: 'Please verify your email before logging in.' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email, full_name: user.full_name, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                full_name: user.full_name,
                email: user.email,
                role: user.role,
                phone: user.phone,
                institution: user.institution,
            },
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * GET /api/verify-email
 * Verifies a user's email using the verification token
 */
const verifyEmail = async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).json({ error: 'Verification token is required.' });
    }

    try {
        // Find user by verification token
        const [results] = await User.findByVerificationToken(token);
        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired verification token.' });
        }

        // Mark user as verified
        await User.verify(results[0].id);

        res.json({ message: 'Email verified successfully! You can now log in.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * POST /api/forgot-password
 * Initiates password reset by sending a reset email
 */
const forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required.' });
    }

    try {
        // Find user by email
        const [results] = await User.findByEmail(email);

        // Security: Always return the same message to prevent email enumeration
        if (results.length === 0) {
            return res.json({ message: 'If an account exists, a reset link has been sent.' });
        }

        const user = results[0];

        // Generate reset token (expires in 1 hour)
        const reset_token = uuidv4();
        const expires = new Date(Date.now() + 3600000);

        // Save reset token to database
        await User.setResetToken(user.id, reset_token, expires);

        // Send reset email
        await sendPasswordResetEmail(email, reset_token);

        res.json({ message: 'If an account exists, a reset link has been sent.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * POST /api/reset-password
 * Resets a user's password using the reset token
 */
const resetPassword = async (req, res) => {
    // We added 'email' to what we extract from the request
    const { email, password } = req.body;

    // If there is no email or password, tell the user exactly that
    if (!email || !password) {
        return res.status(400).json({ error: 'Missing email or password in request.' });
    }

    try {
        // 1. Find the user by email instead of token
        const [results] = await User.findByEmail(email);

        if (results.length === 0) {
            return res.status(404).json({ error: 'No account found with this email.' });
        }

        const user = results[0];

        // 2. Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashed_password = await bcrypt.hash(password, salt);

        // 3. Update the password in the database
        await User.updatePassword(user.id, hashed_password);

        // 4. THE MAGIC LINE: Mark them as verified immediately
        await User.verify(user.id);

        return res.json({ message: 'Success! Your account is now verified.' });
    } catch (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ error: 'Server database error' });
    }
};

module.exports = { register, login, verifyEmail, forgotPassword, resetPassword };