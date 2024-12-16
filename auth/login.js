const express = require('express');
const { commonMiddlewares, createRateLimiter } = require('./middleware/commonMiddleware');
const { generateTokens } = require('./middleware/authMiddleware')
const xss = require('xss');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const pool = require('../db');
const loginRouter = express.Router();

// Middleware
commonMiddlewares(loginRouter);

// Rate Limiting
const loginRouterLimiter = createRateLimiter(5 * 60 * 1000, 10, "Too many login attempts, please try again later.");
loginRouter.use(loginRouterLimiter);

loginRouter.post('/',
    [
        body('username')
            .notEmpty().withMessage('Username is required')
            .isString().withMessage('Username must be a string')
            .trim().escape()
            .isLength({ max: 255 }).withMessage('Username must be at most 255 characters long')
            .customSanitizer(value => xss(value)),
        body('passphrase')
            .notEmpty().withMessage('Password is required')
            .isString().withMessage('Password must be a string')
            .trim().escape()
            .isLength({ min: 6 }).withMessage('Password must be 6 characters long')
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

        const { username, passphrase } = req.body;

        try {
            const userResult = await pool.query(`
                    SELECT 
                        u.userno, u.peopleno, u.passphrase, u.userstatusno, 
                        ur.userroleno, ur.validuntil, 
                        us.userstatustitle,
                        pp.dob, pp.profilepicurl
                    FROM 
                        (
                            SELECT 
                                userno,username,passphrase,peopleno,userstatusno
                            FROM gen_users
                            WHERE username = $1
                        ) AS u
                        INNER JOIN (
                            SELECT 
                                userno,userroleno,validuntil
                            FROM gen_userroles
                            WHERE userroleno IN (
                                    SELECT userroleno
                                    FROM gen_userrolesetting
                                )
                        ) AS ur
                        ON u.userno = ur.userno
                        INNER JOIN (
                            SELECT userstatusno,userstatustitle
                            FROM gen_userstatus
                        ) AS us
                        ON u.userstatusno = us.userstatusno
                        INNER JOIN (
                            SELECT peopleno, dob, profilepicurl
                            FROM gen_peopleprimary
                        ) AS pp
                        ON u.peopleno = pp.peopleno
                `, [username]
            );

            if (userResult.rowCount === 0) {
                return res.status(401).json({ 
                    error: true,
                    message: 'Invalid user' 
                });
            }

            const user = userResult.rows[0];

            // Compare the provided password with the stored hash
            const isMatch = await bcrypt.compare(passphrase, user.passphrase);

            if (!isMatch) {
                return res.status(401).json({ 
                    error: true,
                    message: 'Invalid password' 
                });
            }

            // Check if the user is active
            if (user.userstatusno !== 1) {
                return res.status(403).json({ 
                    error: true,
                    message: `Account status: ${user.userstatustitle}` 
                });
            }

            // Check the validity of the user role
            if (user.validuntil && new Date(user.validuntil) < new Date()) {
                return res.status(403).json({
                    error: true,
                    message: 'User role has expired'
                });
            }

            // Calculate age from dob
            const calculateAge = (dob) => {
                const birthDate = new Date(dob);
                const today = new Date();
                let age = today.getFullYear() - birthDate.getFullYear();
                const monthDiff = today.getMonth() - birthDate.getMonth();
                if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
                    age--;
                }
                return age;
            };

            const age = calculateAge(user.dob);

            // Get current time
            const currentTime = new Date().toISOString();

            const payload = {
                userno: user.userno,
                peopleno: user.peopleno,
                userroleno: user.userroleno,
                age: age,
                profilepicurl: user.profilepicurl,
                currenttime: currentTime
            }; 
            
            // Generate JWT token and refresh token using generateTokens function
            const { accessToken, refreshToken } = generateTokens(payload);

            res.status(200).json({
                message: 'Login successful',
                token: accessToken,
                refreshToken: refreshToken
            });

        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.detail });
        }
    }
);

module.exports = loginRouter;