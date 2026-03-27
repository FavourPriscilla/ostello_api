/**
 * controllers/hostelController.js – Hostel Management Controller
 *
 * Endpoints:
 *   GET    /api/hostels              → search/list hostels (public)
 *   GET    /api/hostels/:id          → get hostel details (public)
 *   POST   /api/hostels              → create hostel (CUSTODIAN)
 *   PUT    /api/hostels/:id          → update hostel (CUSTODIAN owner)
 *   DELETE /api/hostels/:id          → delete hostel (CUSTODIAN owner / ADMIN)
 *   GET    /api/hostels/my           → get custodian's own hostels
 *   GET    /api/hostels/stats        → dashboard stats
 */

const Hostel = require('../models/hostelModel');

/**
 * GET /api/hostels
 * Public search with filters.
 * Query params: search, min_price, max_price, amenity, min_rating,
 *               room_type, lat, lng, radius
 */
const searchHostels = async (req, res) => {
    try {
        const [hostels] = await Hostel.search(req.query);
        
        // Parse JSON fields for each hostel
        const parsedHostels = hostels.map(hostel => ({
            ...hostel,
            photos: typeof hostel.photos === 'string' ? JSON.parse(hostel.photos) : hostel.photos,
            amenities: typeof hostel.amenities === 'string' ? JSON.parse(hostel.amenities) : hostel.amenities,
        }));
        
        res.json(parsedHostels);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * GET /api/hostels/my – Get hostels owned by the logged-in custodian
 */
const getMyHostels = async (req, res) => {
    try {
        const [hostels] = await Hostel.getByCustodian(req.user.id);
        
        // Parse JSON fields for each hostel
        const parsedHostels = hostels.map(hostel => ({
            ...hostel,
            photos: typeof hostel.photos === 'string' ? JSON.parse(hostel.photos) : hostel.photos,
            amenities: typeof hostel.amenities === 'string' ? JSON.parse(hostel.amenities) : hostel.amenities,
        }));
        
        res.json(parsedHostels);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * GET /api/hostels/stats – Dashboard stats
 */
const getStats = async (req, res) => {
    try {
        let stats;
        if (req.user.role === 'ADMIN') {
            stats = await Hostel.getAdminStats();
        } else {
            stats = await Hostel.getCustodianStats(req.user.id);
        }
        res.json(stats);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * GET /api/hostels/:id – Public; get hostel details
 */
const getHostelById = async (req, res) => {
    try {
        const [results] = await Hostel.getById(req.params.id);
        if (results.length === 0) {
            return res.status(404).json({ error: 'Hostel not found.' });
        }

        // Parse JSON fields
        const hostel = results[0];
        hostel.photos = typeof hostel.photos === 'string' ? JSON.parse(hostel.photos) : hostel.photos;
        hostel.amenities = typeof hostel.amenities === 'string' ? JSON.parse(hostel.amenities) : hostel.amenities;

        res.json(hostel);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * POST /api/hostels – Create a hostel (CUSTODIAN only)
 * Body: { name, description, address, latitude, longitude, photos, amenities }
 */
const createHostel = async (req, res) => {
    const { name, description, address, latitude, longitude, photos, amenities } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Hostel name is required.' });
    }

    try {
        const [result] = await Hostel.create({
            custodian_id: req.user.id,
            name,
            description,
            address,
            latitude,
            longitude,
            photos,
            amenities,
        });

        res.status(201).json({
            message: 'Hostel created successfully.',
            hostelId: result.insertId,
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * PUT /api/hostels/:id – Update hostel (owner CUSTODIAN only)
 */
const updateHostel = async (req, res) => {
    const hostelId = req.params.id;

    try {
        // Verify ownership
        const [results] = await Hostel.getById(hostelId);
        if (results.length === 0) {
            return res.status(404).json({ error: 'Hostel not found.' });
        }
        if (results[0].custodian_id !== req.user.id && req.user.role !== 'ADMIN') {
            return res.status(403).json({ error: 'You can only update your own hostels.' });
        }

        const { name, description, address, latitude, longitude, photos, amenities } = req.body;
        await Hostel.update(hostelId, { name, description, address, latitude, longitude, photos, amenities });
        res.json({ message: 'Hostel updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * DELETE /api/hostels/:id – Delete hostel (owner CUSTODIAN or ADMIN)
 */
const deleteHostel = async (req, res) => {
    const hostelId = req.params.id;

    try {
        const [results] = await Hostel.getById(hostelId);
        if (results.length === 0) {
            return res.status(404).json({ error: 'Hostel not found.' });
        }
        if (results[0].custodian_id !== req.user.id && req.user.role !== 'ADMIN') {
            return res.status(403).json({ error: 'You can only delete your own hostels.' });
        }

        await Hostel.delete(hostelId);
        res.json({ message: 'Hostel deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

module.exports = { searchHostels, getMyHostels, getStats, getHostelById, createHostel, updateHostel, deleteHostel };
