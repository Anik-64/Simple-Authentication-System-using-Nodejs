const express = require('express');
const { commonMiddlewares, createRateLimiter } = require('./middleware/commonMiddleware');
const xss = require('xss');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const pool = require('../db'); 
require("dotenv").config();

const passwordResetRouter = express.Router();

// Security Middlewares
commonMiddlewares(passwordResetRouter);

// Rate Limiting
const passwordResetLimiter = createRateLimiter(60 * 60 * 1000, 5, "Too many OTP requests from this user. Please try again later.");
passwordResetRouter.use(passwordResetLimiter);

// Generate OTP
const generateOtp = (length) => {
    return crypto.randomInt(Math.pow(10, length - 1), Math.pow(10, length)).toString().padStart(length, '0');
};

// This route will send otp requests
passwordResetRouter.post('/sendotp',
    [
        body('username')
            .notEmpty().withMessage('Username is required')
            .isString().withMessage('Username must be a string')
            .trim().escape()
            .isLength({ max: 255 }).withMessage('Username must be at most 255 characters long')
            .customSanitizer(value => xss(value)),
        body('otpLength')
            .optional()
            .isInt({ min: 4, max: 6 }).withMessage('OTP length must be an integer and between 4 and 6')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Map errors and return the first message
            const errorMessages = errors.array().map(err => err.msg);
            return res.status(400).json({
                error: true,
                message: errorMessages[0]
            });
        }
        
        const { username, otpLength } = req.body;
        const otpLengthToUse = otpLength || 4; // Default OTP length is 4
    
        try {
            // Check if the user exists in gen_users table
            const userResult = await pool.query(`
                    SELECT userno, peopleno 
                    FROM gen_users 
                    WHERE username = $1
                        AND peopleno IN (
                                SELECT peopleno
                                FROM gen_peopleprimary
                            )
                `, [username]
            );
    
            if (userResult.rowCount === 0) {
                return res.status(404).json({
                    error: true,
                    message: 'Please register first' 
                });
            }
    
            const { userno, peopleno } = userResult.rows[0];
    
            // Check the provided email in the gen_peopleprimary
            const emailResult = await pool.query(`
                    SELECT email 
                    FROM gen_peopleprimary 
                    WHERE peopleno = $1
                `, [peopleno]
            );

            const email = emailResult.rows[0].email;
    
            // Generate OTP
            const otp = generateOtp(otpLengthToUse);
    
            // Calculate expiry time (15 minutes from now)
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
            
            // Insert OTP into userrecovery table
            const insertQuery = `
                INSERT INTO userrecovery (userno, otp, via, expires_at)
                VALUES ($1, $2, $3, $4)
                RETURNING *;
            `;
            await pool.query(insertQuery, [userno, otp, '1', expiresAt]); // Assuming 'via' as '1' for email
            
            // Send OTP to email
            const transporter = nodemailer.createTransport({
                host: 'smtp.ethereal.email',
                port: 587,
                auth: {
                    user: 'taryn.weissnat33@ethereal.email',
                    pass: '3CJeSCvN2Wt7XwbgFX'
                }
            });

            const info = await transporter.sendMail({
                from: '"AGAMiLabs 👻" <agamilabs@gmail.com>', 
                to: `${email}`, 
                subject: "Your OTP Code", 
                text: `Your OTP code is: ${otp}. It will expire in 15 minutes.`, 
                // html: "<b>Hello world?</b>", 
            });
    
            res.status(200).json({ 
                error: false,
                message: 'OTP sent successfully', 
                info: info.messageId // Optionally return the message ID
            });
    
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.detail });
        }
    }
);

// Reset password
passwordResetRouter.post('/resetpassword',
    [
        body('username')
            .notEmpty().withMessage('Username is required')
            .isString().withMessage('Username must be a string')
            .trim().escape()
            .isLength({ max: 255 }).withMessage('Username must be at most 255 characters long')
            .customSanitizer(value => xss(value)),
        body('otp')
            .notEmpty().withMessage('OTP is required')
            .isString().withMessage('OTP must be a string')
            .trim().escape()
            .isLength({ max: 6 }).withMessage('OTP must be at most 6 characters long')
            .customSanitizer(value => xss(value)),
        body('passphrase')
            .notEmpty().withMessage('Password is required')
            .isString().withMessage('Password must be a string')
            .trim().escape()
            .isLength({ max: 255 }).withMessage('Password must be at most 255 characters long')
            .customSanitizer(value => xss(value))
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Map errors and return the first message
            const errorMessages = errors.array().map(err => err.msg);
            return res.status(400).json({
                error: true,
                message: errorMessages[0]
            });
        }

        const { username, otp, passphrase } = req.body;
    
        try {
            // Fetch the most recent OTP for the user
            const otpResult = await pool.query(`
                SELECT otp, userno, sent_at, expires_at
                FROM userrecovery
                WHERE userno = (
                    SELECT userno 
                    FROM gen_users 
                    WHERE username = $1
                )
                ORDER BY sent_at DESC
                LIMIT 1;
            `, [username]);

            // Check if any OTP was found
            if (otpResult.rowCount === 0) {
                return res.status(400).json({ 
                    error: true,
                    message: 'Invalid OTP or user not found' 
                });
            }

            const { otp: storedOtp, userno, expires_at } = otpResult.rows[0];

            // Check if the OTP is valid and not expired
            const currentTime = new Date();
            if (currentTime > new Date(expires_at)) {
                return res.status(400).json({ 
                    error: true,
                    message: 'OTP has expired' 
                });
            }

            if (storedOtp.trim() !== otp.trim()) {
                return res.status(400).json({
                    error: true,
                    message: "Invalid OTP",
                });
            }
    
            // Hash the new password
            const hashedPassword = await bcrypt.hash(passphrase, 10);
    
            // Update the user's password in the gen_users table
            await pool.query(`
                    UPDATE gen_users 
                    SET passphrase = $1 
                    WHERE userno = $2
                `,[hashedPassword, userno]
            );
    
            // Delete the used OTP from the userrecovery table
            await pool.query(`
                    DELETE FROM userrecovery 
                    WHERE otp = $1
                        AND userno IN (
                            SELECT userno
                            FROM gen_users
                            WHERE username = $2
                        )
                `, [otp, username]);

            // Increment the reset_pass_count in the gen_users table
            await pool.query(`
                    UPDATE gen_users 
                    SET reset_pass_count = reset_pass_count + 1
                    WHERE userno = $1
                `, [userno]
            );
    
            res.status(200).json({ 
                error: false,
                message: 'Password updated successfully' 
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Server error' });
        }
    }
);

module.exports = passwordResetRouter;