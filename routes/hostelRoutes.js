/**
 * routes/hostelRoutes.js – Hostel Management Routes
 *
 * Public:
 *   GET /api/hostels           → search/list hostels
 *   GET /api/hostels/:id       → hostel details
 *
 * Protected (CUSTODIAN):
 *   GET    /api/hostels/my     → custodian's hostels
 *   GET    /api/hostels/stats  → dashboard stats
 *   POST   /api/hostels        → create hostel
 *   PUT    /api/hostels/:id    → update hostel
 *   DELETE /api/hostels/:id    → delete hostel
 */

const express = require('express');
const {
    searchHostels, getMyHostels, getStats,
    getHostelById, createHostel, updateHostel, deleteHostel,
} = require('../controllers/hostelController');
const { authenticateToken, authorize } = require('../middleware/authMiddleware');

const router = express.Router();

// Static routes BEFORE :id routes
router.get('/hostels/my', authenticateToken, authorize('CUSTODIAN', 'ADMIN'), getMyHostels);
router.get('/hostels/stats', authenticateToken, authorize('CUSTODIAN', 'ADMIN'), getStats);

// Public routes
router.get('/hostels', searchHostels);
router.get('/hostels/:id', getHostelById);

// Protected routes (CUSTODIAN)
router.post('/hostels', authenticateToken, authorize('CUSTODIAN', 'ADMIN'), createHostel);
router.put('/hostels/:id', authenticateToken, authorize('CUSTODIAN', 'ADMIN'), updateHostel);
router.delete('/hostels/:id', authenticateToken, authorize('CUSTODIAN', 'ADMIN'), deleteHostel);

module.exports = router;