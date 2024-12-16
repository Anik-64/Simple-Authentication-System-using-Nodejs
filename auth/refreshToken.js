// refreshToken.js
const express = require('express');
const jwt = require('jsonwebtoken');
const { generateTokens } = require('../auth/middleware/authMiddleware');
require('dotenv').config();

const refreshRouter = express.Router();
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

refreshRouter.post('/', (req, res) => {
    const refreshToken = req.body.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ 
            error: true, 
            message: 'Refresh token is required' 
        });
    }

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: true, message: 'Invalid or expired refresh token' });

        // Get current time
        currentTime = new Date().toISOString();

        // Remove sensitive information from payload if needed
        const { 
            userno, 
            peopleno,
            userroleno, 
            age, 
            profilepicurl,
        } = user;

        const { accessToken, refreshToken } = generateTokens({ 
            userno, 
            peopleno,
            userroleno, 
            age, 
            profilepicurl,
            currentTime
        });

        res.status(200).json({
            token: accessToken,
            refreshToken: refreshToken
        });
    });
});

module.exports = refreshRouter;