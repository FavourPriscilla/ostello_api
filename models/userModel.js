/**
 * models/userModel.js – User Model (Ostello)
 */
const db = require('../config/db');

class User {
  // --- 1. REGISTRATION & LOGIN METHODS ---

  /**
   * Create a new user in the database
   * @param {Object} userData - User data object
   * @param {string} userData.full_name - User's full name
   * @param {string} userData.email - User's email
   * @param {string} userData.phone - User's phone number
   * @param {string} userData.password - Hashed password
   * @param {string} userData.role - User role (STUDENT/CUSTODIAN)
   * @param {string} userData.institution - User's institution
   * @param {string} userData.verification_token - Email verification token
   */
  static async create(userData) {
    const { full_name, email, phone, password, role, institution, verification_token } = userData;
    const sql = `
      INSERT INTO users (full_name, email, phone, password_hash, role, institution, verification_token)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    return db.execute(sql, [full_name, email, phone, password, role, institution, verification_token]);
  }

  /**
   * Find a user by email address
   * @param {string} email - User's email
   * @returns {Promise<Array>} Database query result
   */
  static async findByEmail(email) {
    const sql = 'SELECT * FROM users WHERE email = ?';
    return db.execute(sql, [email]);
  }

  // --- 2. EMAIL VERIFICATION METHODS ---

  /**
   * Find a user by verification token
   * @param {string} token - Email verification token
   * @returns {Promise<Array>} Database query result
   */
  static async findByVerificationToken(token) {
    const sql = 'SELECT * FROM users WHERE verification_token = ?';
    return db.execute(sql, [token]);
  }

  /**
   * Mark a user as verified and remove verification token
   * @param {number} userId - User's ID
   * @returns {Promise<Array>} Database update result
   */
  static async verify(userId) {
    const sql = 'UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?';
    return db.execute(sql, [userId]);
  }

  // --- 3. PASSWORD RESET METHODS ---

  /**
   * Save reset token and expiry time to database
   * @param {number} userId - User's ID
   * @param {string} token - Reset token
   * @param {Date} expires - Token expiry date
   * @returns {Promise<Array>} Database update result
   */
  static async setResetToken(userId, token, expires) {
    const sql = `
      UPDATE users
      SET reset_password_token = ?,
          reset_password_expires = ?
      WHERE id = ?
    `;
    return db.execute(sql, [token, expires, userId]);
  }

  /**
   * Find user by reset token (only if not expired)
   * @param {string} token - Reset token
   * @returns {Promise<Array>} Database query result
   */
  static async findByResetToken(token) {
    const sql = `
      SELECT * FROM users
      WHERE reset_password_token = ?
      AND reset_password_expires > NOW()
    `;
    return db.execute(sql, [token]);
  }

  /**
   * Update user password and clear reset token
   * @param {number} userId - User's ID
   * @param {string} hashedPassword - New hashed password
   * @returns {Promise<Array>} Database update result
   */
  static async updatePassword(userId, hashedPassword) {
    const sql = `
      UPDATE users
      SET password_hash = ?,
          reset_password_token = NULL,
          reset_password_expires = NULL
      WHERE id = ?
    `;
    return db.execute(sql, [hashedPassword, userId]);
  }
}

module.exports = User;