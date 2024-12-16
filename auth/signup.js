const express = require('express');
const { commonMiddlewares, createRateLimiter } = require('./middleware/commonMiddleware');
const xss = require('xss');
const bcrypt = require('bcrypt');
const { body, validationResult, query } = require('express-validator');
const pool = require('../db'); 
require("dotenv").config();

const registrationRouter = express.Router();

// Security Middlewares
commonMiddlewares(registrationRouter);

// Rate Limiting
const registrationLimiter = createRateLimiter();
registrationRouter.use(registrationLimiter);

// Middleware to verify reCAPTCHA token
const verifyRecaptcha = async (req, res, next) => {
    const recaptchaToken = req.body.recaptchaToken; // Token sent from frontend
    const secretKey = process.env.RECAPTCHA_SECRET_KEY; // Your Secret Key from Google

    if (!recaptchaToken) {
        return res.status(400).json({ error: 'reCAPTCHA token is missing' });
    }

    try {
        // Verify reCAPTCHA token with Google
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
            params: {
                secret: secretKey,
                response: recaptchaToken
            }
        });

        const { success, score, action } = response.data;

        if (!success || score < 0.5) {
        return res.status(403).json({ error: 'Failed reCAPTCHA verification' });
        }

        next();
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        return res.status(500).json({ error: 'Internal server error during reCAPTCHA validation' });
    }
};

/* The above code is a route handler in a Node.js application using Express framework. It is handling a
GET request to check if a username exists in a database table called `gen_users`. Here is a
breakdown of what the code is doing: */
registrationRouter.get('/usernameexists/search',
    [
        query('username')
            .notEmpty().withMessage('Username is required')
            .isString().withMessage('Username must be a string')
            .trim().escape()
            .isLength({ min: 3, max: 255 }).withMessage('Username must be between 3 to 255 characters long')
            .customSanitizer(value => xss(value))
            .custom(value => {
                if (/\s/.test(value)) {
                    throw new Error('Username must not contain spaces');
                }
                return true;
            }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { username } = req.query;

        const query = `
            SELECT username FROM gen_users
            WHERE username = $1;
        `;

        try {
            const result = await pool.query(query, [username]);

            if(result.rowCount === 0) {
                return res.status(404).json({
                    error: false,
                    message: 'No data found !'
                });
            }

            res.status(200).json({
                error: true,
                message: 'Username exists'
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.detail });
        }
    }
);

registrationRouter.post('/',
    [
        body('firstname')
            .notEmpty().withMessage('First name is required')
            .isString().withMessage('First name must be a string')
            .trim().escape()
            .isLength({ max: 127 }).withMessage('First name must be at most 127 characters long')
            .matches(/^[A-Za-z. ]+$/).withMessage('First name can contain only letters, periods, and spaces')
            .customSanitizer(value => {
                return xss(
                    value.split(' ')
                        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                        .join(' ')
                );
            }),
        body('lastname')
            .optional()
            .isString().withMessage('Last name must be a string')
            .trim().escape()
            .isLength({ max: 127 }).withMessage('Last name must be at most 127 characters long')
            .matches(/^[a-zA-Z ]+$/).withMessage('First name must contain only alphabetic characters')
            .customSanitizer(value => {
                return xss(
                    value.split(' ')
                        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                        .join(' ')
                );
            }),
        body('countrycode')
            .optional()
            .isString().withMessage('Country code must be a string')
            .trim().escape()
            .isLength({ max: 5 }).withMessage('Country code must be at most 5 characters long')
            .customSanitizer(value => xss(value)),
        body('contactno')
            .notEmpty().withMessage('Contact number is required')
            .isString().withMessage('Contact number must be a string')
            .trim().escape()
            .isLength({ max: 20 }).withMessage('Contact number must be at most 20 characters long')
            .customSanitizer(value => xss(value)),
        body('dob')
            .notEmpty().withMessage('Date of birth is required')
            .isISO8601().withMessage('Invalid date format, expected YYYY-MM-DD'),
        body('email')
            .notEmpty().withMessage('Email is required')
            .isString().withMessage('Email must be a string')
            .trim().escape()
            .isEmail().withMessage('Invalid email format')
            .isLength({ max: 255 }).withMessage('Email must be at most 255 characters long')
            .customSanitizer(value => xss(value)),
        body('passphrase')
            .notEmpty().withMessage('Password is required')
            .isString().withMessage('Password must be a string')
            .trim().escape()
            .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
            .customSanitizer(value => xss(value)),
        body('username')
            .notEmpty().withMessage('Username is required')
            .isString().withMessage('Username must be a string')
            .trim().escape()
            .isLength({ min: 3, max: 255 }).withMessage('Username must be between 3 to 255 characters long')
            .customSanitizer(value => xss(value))
            .custom(value => {
                if (/\s/.test(value)) {
                    throw new Error('Username must not contain spaces');
                }
                return true;
            }),
        body('userroleno')
            .notEmpty().withMessage('User role number is required')
            .isInt().withMessage('User role number must be an integer')
    ],
    async (req, res) => {
        console.log(req.headers);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Map errors and return the first message
            const errorMessages = errors.array().map(err => err.msg);
            return res.status(400).json({
                error: true,
                message: errorMessages[0]
            });
        }

        const { firstname, lastname, countrycode = '+880', dob, email, 
            passphrase, username, userroleno} = req.body;

        let { contactno } = req.body;

        try {
            // Check if the username or email already exists
            const existingUser = await pool.query(`
                    SELECT username FROM gen_users 
                    WHERE username = $1
                `, [username]
            );

            if (existingUser.rowCount > 0) {
                return res.status(400).json({ 
                    error: true,
                    message: 'Username already exists'
                });
            }

            // If the country code is '+880' and the contact number starts with '0', remove the leading '0'
            if (countrycode === '+880' && contactno.startsWith('0')) {
                contactno = contactno.substring(1); // Remove the leading '0'
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(passphrase, 10);

            // Insert the user's basic information into gen_peopleprimary
            const peopleResult = await pool.query(`
                    INSERT INTO gen_peopleprimary 
                        (firstname, lastname, countrycode, contactno, dob, gender, email) 
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING peopleno;
                `, [firstname, lastname, countrycode, contactno, dob, 'Not mentioned', email]
            );

            const peopleno = peopleResult.rows[0].peopleno;

            // Insert the user's login credentials into gen_users
            const userResult = await pool.query(`
                    INSERT INTO gen_users 
                    (peopleno, username, passphrase) 
                    VALUES ($1, $2, $3)
                    RETURNING userno;
                `, [peopleno, username, hashedPassword]
            );

            const userno = userResult.rows[0].userno;

            // Insert into gen_userroles
            await pool.query(`
                    INSERT INTO gen_userroles (userno, userroleno)
                    VALUES ($1, $2);
                `, [userno, userroleno]
            );

            // res.cookie("csrf_token", csrf_token);

            res.status(201).json({
                error: false,
                message: 'Registration successful',
                userId: userResult.rows[0].userno
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.detail });
        }
    }
);

module.exports = registrationRouter;