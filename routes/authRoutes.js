/**
 * routes/authRoutes.js – Authentication Routes (Ostello)
 *
 * Public routes:
 *   POST /api/register         → register with role
 *   POST /api/login            → authenticate
 *   GET  /api/verify-email     → verify email
 *   POST /api/forgot-password  → request password reset
 *   POST /api/reset-password   → reset password
 */

const express = require('express');
const { register, login, verifyEmail, forgotPassword, resetPassword } = require('../controllers/authController');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/verify-email', verifyEmail);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

module.exports = router;
const handleSubmit = async (e) => {
  e.preventDefault();
  
  const userData = {
    fullName,
    email,
    password,
    phone_number: phone // <--- Add this line to the object
  };

  // Your fetch or axios call follows...
};