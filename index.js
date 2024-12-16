// Dependencies
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const fs = require('fs');
const path = require("path");
// const routers = require('./routers/routers');
const { login, signup, passwordReset, refreshToken, authenticateToken, authorizeRoles } = require('./auth/routers/authRouters.js');

require('./backgroundWorker.js');
require('dotenv').config();

const app = express();
app.use(express.json());

const corsOptions = {
    origin: '*',
    credentials: true, 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
};

app.use(cors(corsOptions));

// Log file
const logStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
morgan.token('body', (req) => {
    const body = { ...req.body };
    if (body.password) body.password = '*****';
    return JSON.stringify(body);
});

app.use(morgan(':date[iso] :method :url :status :response-time ms - :body', { stream: logStream }));
app.use(morgan('dev'));

// Routers
app.use('/signup', signup);
app.use('/login', login);
app.use('/password-reset', passwordReset);
app.use('/refresh-token', refreshToken);

// app.use('/patientvisit', authenticateToken, authorizeRoles([1, 3, 5, 6, 7]), routers.patientVisitRouter);

// Start the server
app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});