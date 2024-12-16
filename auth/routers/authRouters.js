// Dependencies
const login = require("../login");
const signup = require("../signup");
const passwordReset = require("../passwordReset");
const refreshToken = require("../refreshToken");
const { authenticateToken, authorizeRoles} = require("../middleware/authMiddleware");

module.exports = {
    login,
    signup,
    passwordReset,
    refreshToken,
    authenticateToken,
    authorizeRoles
};
