const express = require('express');
const bcrypt = require('bcryptjs'); // for hashing and salting
const jwt = require('jsonwebtoken'); // for tokens
const Employee = require('../models/Employee'); // Employee model
const { check, validationResult } = require('express-validator'); // import express-validator
const router = express.Router();

// Employee login route
router.post(
  '/login',
  [
    // Updated input validation for login
    check('username')
      .matches(/^employee\d+$/) // Allows "employee" followed by one or more digits
      .withMessage('Username must start with "employee" followed by a number.'),

    check('password')
      .matches(/^[a-zA-Z0-9]{10,}$/) // Allows alphanumeric passwords with a minimum length of 10
      .withMessage(
        'Password must be at least 10 characters long and alphanumeric.'
      ),
  ],
  async (req, res) => {
    // For validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body; // Updated to use 'username'

    try {
      // Find employee by username
      const employee = await Employee.findOne({ username });
      if (!employee) return res.status(401).json({ message: 'Invalid credentials' });

      // Compare passwords
      const isMatch = await bcrypt.compare(password, employee.password);
      if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

      // Generate token for employee login
      const token = jwt.sign({ id: employee._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (error) {
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

module.exports = router;
