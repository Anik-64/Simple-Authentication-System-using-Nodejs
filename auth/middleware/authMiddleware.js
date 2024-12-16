const jwt = require('jsonwebtoken');
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Generates both access and refresh tokens
const generateTokens = (payload) => {
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: '7d' }); // Valid for 7 days

    return { accessToken, refreshToken };
};


// Function to validate JWT token
const authenticateToken = (req, res, next) => {
    // Get the token from the request headers
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            error: true,
            message: 'Access denied, token missing!'
        });
    }

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // Check for specific expiration error
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ 
                    error: true,
                    message: 'Token has expired!'
                });
            }

            return res.status(403).json({ 
                error: true,
                message: 'Invalid token!'
            });
        }

        req.user = user;
        next();
    });
};

/**
 * The `authorizeRoles` function checks if the user's role is included in the allowed roles and returns
 * an error message if not.
 * @param allowedRoles - The `allowedRoles` parameter in the `authorizeRoles` function is an array that
 * contains the roles that are allowed to access a particular route or resource. The function checks if
 * the user making the request has a role that is included in the `allowedRoles` array. If the user's
 * role is
 * @returns The `authorizeRoles` function returns a middleware function that checks if the user role in
 * the request matches any of the allowed roles. If the user role is not included in the allowed roles,
 * it returns a 403 status with an error message indicating insufficient permissions. If the user role
 * is allowed, it calls the `next()` function to proceed to the next middleware in the chain.
 */
// Function to authorize based on user roles
const authorizeRoles = (allowedRoles) => (req, res, next) => {
    try {
        const userRole = req.user?.userroleno;
    
        if (!allowedRoles.includes(userRole)) {
            return res.status(403).json({
                error: true,
                message: 'Access denied, insufficient permissions!',
            });
        }
    
        next();
    } catch(err) {
        res.status(500).json({ error: "An error occurred while authorizing the user" });
    }
};

// // need to use this to verify appcheck token
// const appCheckVerification = async (req, res, next) => {
//     const appCheckToken = req.header("X-Firebase-AppCheck");

//     if (!appCheckToken) {
//         res.status(401);
//         return next("Unauthorized");
//     }

//     try {
//         const appCheckClaims = await getAppCheck().verifyToken(appCheckToken);

//         // If verifyToken() succeeds, continue with the next middleware
//         // function in the stack.
//         return next();
//     } catch (err) {
//         res.status(401);
//         return next("Unauthorized");
//     }
// }


module.exports = {
    generateTokens,
    authenticateToken,
    authorizeRoles
};
