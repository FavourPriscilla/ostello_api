/**
 * models/roomModel.js – Data Access Layer for Rooms
 */

const db = require('../config/db');

const Room = {
    /**
     * Create a new room in a hostel.
     */
    create: ({ hostel_id, room_number, room_type, price_per_semester, capacity, description, is_available }) => {
        const sql = `INSERT INTO rooms
      (hostel_id, room_number, room_type, price_per_semester, capacity, description, is_available)
      VALUES (?, ?, ?, ?, ?, ?, ?)`;
        return db.query(sql, [
            hostel_id,
            room_number || null,
            room_type || 'SINGLE',
            price_per_semester,
            capacity || 1,
            description || null,
            is_available !== undefined ? is_available : true,
        ]);
    },

    /**
     * Get all rooms for a hostel.
     */
    getByHostel: (hostel_id) => {
        const sql = 'SELECT * FROM rooms WHERE hostel_id = ? ORDER BY room_type, price_per_semester';
        return db.query(sql, [hostel_id]);
    },

    /**
     * Get a single room by ID.
     */
    getById: (id) => {
        const sql = `SELECT r.*, h.name AS hostel_name, h.custodian_id
                 FROM rooms r
                 JOIN hostels h ON r.hostel_id = h.id
                 WHERE r.id = ?`;
        return db.query(sql, [id]);
    },

    /**
     * Update a room.
     */
    update: (id, { room_number, room_type, price_per_semester, capacity, description, is_available }) => {
        const sql = `UPDATE rooms SET
      room_number = ?, room_type = ?, price_per_semester = ?, capacity = ?, description = ?, is_available = ?
      WHERE id = ?`;
        return db.query(sql, [room_number, room_type, price_per_semester, capacity, description, is_available, id]);
    },

    /**
     * Update room availability.
     */
    setAvailability: (id, is_available) => {
        const sql = 'UPDATE rooms SET is_available = ? WHERE id = ?';
        return db.query(sql, [is_available, id]);
    },

    /**
     * Delete a room.
     */
    delete: (id) => {
        const sql = 'DELETE FROM rooms WHERE id = ?';
        return db.query(sql, [id]);
    },
};

module.exports = Room;
