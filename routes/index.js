import express from "express";
import { getUsers, Login, Register, Logout } from "../controller/Users.js"; 
import { verifyRefreshToken } from "../middleware/refreshToken.js";
import jwt from "jsonwebtoken"; // Import jwt for token handling

const router = express.Router();

// Middleware to check if the user is already logged in
const checkAuth = (req, res, next) => {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) return next(); // If there's no access token, proceed to the next middleware

    jwt.verify(accessToken, process.env.JWT_SECRET, (err, user) => {
        if (err) return next(); // If verification fails, proceed to the next middleware
        req.user = user; // Attach the user information to the request
        return res.status(403).json({ msg: 'User is already logged in' });
    });
};

// Route to get all users
router.get('/users', getUsers);

// Route to register a new user
router.post('/register', checkAuth, Register);

// Route to log in a user
router.post('/login', checkAuth, Login);

// Route to log out a user
router.post('/logout', Logout);

// Route to refresh the access token
router.post('/token', verifyRefreshToken, (req, res) => {
    const accessToken = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
});

export default router;
