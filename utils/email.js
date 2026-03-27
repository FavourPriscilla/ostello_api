/**
 * utils/email.js – Email Sending Utility
 *
 * Uses nodemailer with SMTP. Configure SMTP_HOST, SMTP_PORT,
 * SMTP_USER, SMTP_PASS in .env.
 */

const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

/**
 * Send an email.
 * @param {string} to – recipient email
 * @param {string} subject – email subject line
 * @param {string} html – HTML content body
 * @returns {Promise<void>}
 */
const sendEmail = async (to, subject, html) => {
    try {
        await transporter.sendMail({
            from: `"Ostello" <${process.env.SMTP_USER || 'noreply@ostello.com'}>`,
            to,
            subject,
            html,
        });
        console.log(`✓ Email sent to ${to}: ${subject}`);
    } catch (err) {
        console.error('✗ Email send error:', err.message);
        // Don't throw — email failure shouldn't break the request flow
    }
};

/**
 * Send a verification email with a link.
 * @param {string} email – recipient email
 * @param {string} token – email verification token
 * @returns {Promise<void>}
 */
const sendVerificationEmail = (email, token) => {
    const url = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    const html = `
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto;">
      <h2 style="color: #1A6B4B;">Welcome to Ostello! 🏠</h2>
      <p>Thank you for registering. Please verify your email address to activate your account.</p>
      <a href="${url}" style="display: inline-block; background: #1A6B4B; color: white; padding: 12px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 16px 0;">
        Verify Email
      </a>
      <p style="color: #777; font-size: 13px;">If the button doesn't work, copy and paste this URL:<br/>${url}</p>
    </div>
  `;
    return sendEmail(email, 'Verify Your Ostello Account', html);
};

/**
 * Send a password reset email with a link.
 * Includes debugging console output for the reset token.
 * @param {string} email – recipient email
 * @param {string} token – password reset token
 * @returns {Promise<void>}
 */
const sendPasswordResetEmail = async (email, token) => {
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    
    // Debug output: log reset link (useful for development/testing)
    console.log('-----------------------------------------');
    console.log('PASSWORD RESET LINK:', resetLink);
    console.log('-----------------------------------------');

    const html = `
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto;">
      <h2 style="color: #1A6B4B;">Password Reset 🔐</h2>
      <p>You requested a password reset for your Ostello account. Click the button below to set a new password.</p>
      <a href="${resetLink}" style="display: inline-block; background: #1A6B4B; color: white; padding: 12px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 16px 0;">
        Reset Password
      </a>
      <p style="color: #777; font-size: 13px;">This link expires in 1 hour. If you didn't request this, please ignore this email.</p>
    </div>
  `;
    return sendEmail(email, 'Reset Your Ostello Password', html);
};
module.exports = { sendEmail, sendVerificationEmail, sendPasswordResetEmail };
