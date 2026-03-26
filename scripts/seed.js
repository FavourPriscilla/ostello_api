/**
 * scripts/seed.js – Database Schema & Seed Data for Ostello
 *
 * Creates all tables and inserts sample data.
 * Run: npm run seed
 */

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();

async function seed() {
  const db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
  });

  console.log('Connected to database. Running Ostello seed...\n');

  // ── Drop existing tables (in reverse dependency order) ──────────────────────
  await db.execute('SET FOREIGN_KEY_CHECKS = 0');
  const tables = ['reviews', 'payments', 'bookings', 'rooms', 'hostels', 'users'];
  for (const table of tables) {
    await db.execute(`DROP TABLE IF EXISTS ${table}`);
  }
  await db.execute('SET FOREIGN_KEY_CHECKS = 1');
  console.log('✔  Dropped existing tables');

  // ── Users Table ─────────────────────────────────────────────────────────────
  await db.execute(`
    CREATE TABLE users (
      id                   INT AUTO_INCREMENT PRIMARY KEY,
      full_name            VARCHAR(150) NOT NULL,
      email                VARCHAR(200) NOT NULL UNIQUE,
      phone                VARCHAR(20),
      password_hash        VARCHAR(255) NOT NULL,
      role                 ENUM('STUDENT', 'CUSTODIAN', 'ADMIN') DEFAULT 'STUDENT',
      institution          VARCHAR(200),
      is_verified          BOOLEAN DEFAULT FALSE,
      verification_token   VARCHAR(255),
      reset_token          VARCHAR(255),
      reset_token_expires  DATETIME,
      created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log('✔  Table: users');

  // ── Hostels Table ───────────────────────────────────────────────────────────
  await db.execute(`
    CREATE TABLE hostels (
      id             INT AUTO_INCREMENT PRIMARY KEY,
      custodian_id   INT NOT NULL,
      name           VARCHAR(200) NOT NULL,
      description    TEXT,
      address        VARCHAR(300),
      latitude       DECIMAL(10, 8),
      longitude      DECIMAL(11, 8),
      photos         JSON,
      amenities      JSON,
      avg_rating     DECIMAL(2, 1) DEFAULT 0.0,
      created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (custodian_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  console.log('✔  Table: hostels');

  // ── Rooms Table ─────────────────────────────────────────────────────────────
  await db.execute(`
    CREATE TABLE rooms (
      id                  INT AUTO_INCREMENT PRIMARY KEY,
      hostel_id           INT NOT NULL,
      room_number         VARCHAR(20),
      room_type           VARCHAR(50) DEFAULT 'SINGLE',
      price_per_semester  DECIMAL(10, 2) NOT NULL,
      capacity            INT DEFAULT 1,
      description         TEXT,
      is_available        BOOLEAN DEFAULT TRUE,
      created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (hostel_id) REFERENCES hostels(id) ON DELETE CASCADE
    )
  `);
  console.log('✔  Table: rooms');

  // ── Bookings Table ──────────────────────────────────────────────────────────
  await db.execute(`
    CREATE TABLE bookings (
      id              INT AUTO_INCREMENT PRIMARY KEY,
      student_id      INT NOT NULL,
      room_id         INT NOT NULL,
      check_in_date   DATE NOT NULL,
      check_out_date  DATE NOT NULL,
      status          ENUM('PENDING', 'APPROVED', 'DECLINED', 'CANCELLED', 'COMPLETED') DEFAULT 'PENDING',
      created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (room_id)    REFERENCES rooms(id) ON DELETE CASCADE
    )
  `);
  console.log('✔  Table: bookings');

  // ── Payments Table ──────────────────────────────────────────────────────────
  await db.execute(`
    CREATE TABLE payments (
      id               INT AUTO_INCREMENT PRIMARY KEY,
      booking_id       INT NOT NULL UNIQUE,
      student_id       INT NOT NULL,
      amount           DECIMAL(10, 2) NOT NULL,
      method           ENUM('MOBILE_MONEY', 'CARD', 'BANK_TRANSFER') DEFAULT 'MOBILE_MONEY',
      status           ENUM('PENDING', 'COMPLETED', 'FAILED') DEFAULT 'PENDING',
      transaction_ref  VARCHAR(100),
      created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
      FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  console.log('✔  Table: payments');

  // ── Reviews Table ───────────────────────────────────────────────────────────
  await db.execute(`
    CREATE TABLE reviews (
      id          INT AUTO_INCREMENT PRIMARY KEY,
      student_id  INT NOT NULL,
      hostel_id   INT NOT NULL,
      booking_id  INT NOT NULL UNIQUE,
      rating      TINYINT NOT NULL CHECK (rating >= 1 AND rating <= 5),
      comment     TEXT,
      created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (hostel_id)  REFERENCES hostels(id) ON DELETE CASCADE,
      FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE
    )
  `);
  console.log('✔  Table: reviews\n');

  // ══════════════════════════════════════════════════════════════════════════════
  // ── SEED DATA ─────────────────────────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════════════════════

  const hash = await bcrypt.hash('password123', 10);

  // ── Users ───────────────────────────────────────────────────────────────────
  const users = [
    { full_name: 'Admin User', email: 'admin@ostello.com', role: 'ADMIN', institution: 'Ostello Platform' },
    { full_name: 'John Mukasa', email: 'john@ostello.com', role: 'CUSTODIAN', institution: null },
    { full_name: 'Grace Namuddu', email: 'grace@ostello.com', role: 'CUSTODIAN', institution: null },
    { full_name: 'Alice Namutebi', email: 'alice@student.mak.ac.ug', role: 'STUDENT', institution: 'Makerere University' },
    { full_name: 'Bob Ssekandi', email: 'bob@student.mak.ac.ug', role: 'STUDENT', institution: 'Makerere University' },
    { full_name: 'Diana Kato', email: 'diana@student.ucu.ac.ug', role: 'STUDENT', institution: 'Uganda Christian University' },
  ];

  for (const u of users) {
    await db.execute(
      `INSERT INTO users (full_name, email, phone, password_hash, role, institution, is_verified)
       VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
      [u.full_name, u.email, '+256700000000', hash, u.role, u.institution]
    );
  }
  console.log(`✔  Seeded ${users.length} users (all verified, password: password123)`);

  // ── Hostels ─────────────────────────────────────────────────────────────────
  // Custodian IDs: John=2, Grace=3
  const hostels = [
    {
      custodian_id: 2,
      name: 'Mukasa Heights Hostel',
      description: 'Modern hostel with spacious rooms near Makerere University. 24/7 security, free Wi-Fi, and study rooms available.',
      address: 'Wandegeya, Kampala',
      latitude: 0.3380,
      longitude: 32.5697,
      photos: JSON.stringify(['https://images.unsplash.com/photo-1555854877-bab0e564b8d5?w=800']),
      amenities: JSON.stringify(['WiFi', 'Security', 'Study Room', 'Parking', 'Laundry']),
    },
    {
      custodian_id: 2,
      name: 'Greenview Residences',
      description: 'Affordable student accommodation with a green environment. Walking distance to campus.',
      address: 'Kikoni, Kampala',
      latitude: 0.3355,
      longitude: 32.5630,
      photos: JSON.stringify(['https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800']),
      amenities: JSON.stringify(['WiFi', 'Security', 'Kitchen', 'Water Tank']),
    },
    {
      custodian_id: 3,
      name: 'Grace Court Hostel',
      description: 'Premium hostel for students who value comfort. Fully furnished rooms with en-suite bathrooms.',
      address: 'Mukono Town',
      latitude: 0.3536,
      longitude: 32.7551,
      photos: JSON.stringify(['https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=800']),
      amenities: JSON.stringify(['WiFi', 'Security', 'Gym', 'Kitchen', 'TV Room', 'En-suite']),
    },
    {
      custodian_id: 3,
      name: 'UCU View Hostel',
      description: 'Located right next to UCU campus. Convenient and well-maintained.',
      address: 'Bishop Tucker Rd, Mukono',
      latitude: 0.3530,
      longitude: 32.7590,
      photos: JSON.stringify(['https://images.unsplash.com/photo-1564078516393-cf04bd966897?w=800']),
      amenities: JSON.stringify(['WiFi', 'Security', 'Study Room', 'Canteen']),
    },
  ];

  for (const h of hostels) {
    await db.execute(
      `INSERT INTO hostels (custodian_id, name, description, address, latitude, longitude, photos, amenities)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [h.custodian_id, h.name, h.description, h.address, h.latitude, h.longitude, h.photos, h.amenities]
    );
  }
  console.log(`✔  Seeded ${hostels.length} hostels`);

  // ── Rooms ───────────────────────────────────────────────────────────────────
  const rooms = [
    // Mukasa Heights (hostel 1)
    { hostel_id: 1, room_number: '101', room_type: 'SINGLE', price: 350000, capacity: 1 },
    { hostel_id: 1, room_number: '102', room_type: 'DOUBLE', price: 500000, capacity: 2 },
    { hostel_id: 1, room_number: '103', room_type: 'SINGLE', price: 350000, capacity: 1 },
    // Greenview (hostel 2)
    { hostel_id: 2, room_number: '201', room_type: 'SINGLE', price: 250000, capacity: 1 },
    { hostel_id: 2, room_number: '202', room_type: 'DOUBLE', price: 400000, capacity: 2 },
    // Grace Court (hostel 3)
    { hostel_id: 3, room_number: '301', room_type: 'SINGLE', price: 500000, capacity: 1 },
    { hostel_id: 3, room_number: '302', room_type: 'DOUBLE', price: 750000, capacity: 2 },
    { hostel_id: 3, room_number: '303', room_type: 'DORMITORY', price: 900000, capacity: 6 },
    // UCU View (hostel 4)
    { hostel_id: 4, room_number: '401', room_type: 'SINGLE', price: 300000, capacity: 1 },
    { hostel_id: 4, room_number: '402', room_type: 'DOUBLE', price: 450000, capacity: 2 },
  ];

  for (const r of rooms) {
    await db.execute(
      'INSERT INTO rooms (hostel_id, room_number, room_type, price_per_semester, capacity) VALUES (?, ?, ?, ?, ?)',
      [r.hostel_id, r.room_number, r.room_type, r.price, r.capacity]
    );
  }
  console.log(`✔  Seeded ${rooms.length} rooms`);

  // ── Bookings ────────────────────────────────────────────────────────────────
  const bookings = [
    { student_id: 4, room_id: 1, check_in: '2026-02-01', check_out: '2026-06-30', status: 'COMPLETED' },
    { student_id: 5, room_id: 4, check_in: '2026-03-01', check_out: '2026-07-31', status: 'APPROVED' },
    { student_id: 6, room_id: 6, check_in: '2026-04-01', check_out: '2026-08-31', status: 'PENDING' },
    { student_id: 4, room_id: 9, check_in: '2026-04-15', check_out: '2026-08-15', status: 'PENDING' },
  ];

  for (const b of bookings) {
    await db.execute(
      'INSERT INTO bookings (student_id, room_id, check_in_date, check_out_date, status) VALUES (?, ?, ?, ?, ?)',
      [b.student_id, b.room_id, b.check_in, b.check_out, b.status]
    );
  }
  console.log(`✔  Seeded ${bookings.length} bookings`);

  // ── Payments ────────────────────────────────────────────────────────────────
  await db.execute(
    `INSERT INTO payments (booking_id, student_id, amount, method, status, transaction_ref)
     VALUES (1, 4, 350000, 'MOBILE_MONEY', 'COMPLETED', 'OST-SEED0001')`
  );
  console.log('✔  Seeded 1 payment');

  // Mark room 1 as unavailable (booked)
  await db.execute('UPDATE rooms SET is_available = FALSE WHERE id = 1');

  // ── Reviews ─────────────────────────────────────────────────────────────────
  await db.execute(
    `INSERT INTO reviews (student_id, hostel_id, booking_id, rating, comment)
     VALUES (4, 1, 1, 4, 'Great hostel! Clean rooms and friendly staff. The WiFi could be faster though.')`
  );

  // Update avg_rating for hostel 1
  await db.execute(`
    UPDATE hostels SET avg_rating = (
      SELECT COALESCE(AVG(rating), 0) FROM reviews WHERE hostel_id = 1
    ) WHERE id = 1
  `);
  console.log('✔  Seeded 1 review\n');

  // ── Summary ─────────────────────────────────────────────────────────────────
  console.log('═══════════════════════════════════════════');
  console.log('  Ostello seed complete! 🏠');
  console.log('═══════════════════════════════════════════');
  console.log('');
  console.log('  Login credentials (password: password123):');
  console.log('');
  console.log('  ADMIN:');
  console.log('    admin@ostello.com');
  console.log('');
  console.log('  CUSTODIANS:');
  console.log('    john@ostello.com');
  console.log('    grace@ostello.com');
  console.log('');
  console.log('  STUDENTS:');
  console.log('    alice@student.mak.ac.ug');
  console.log('    bob@student.mak.ac.ug');
  console.log('    diana@student.ucu.ac.ug');
  console.log('');

  await db.end();
}

seed().catch((err) => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});
