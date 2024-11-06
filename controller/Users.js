import Users from "../models/UserModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Get all users
export const getUsers = async (req, res) => {
    try {
        const users = await Users.findAll();
        res.json(users);
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Internal server error' });
    }
};

// Generate access token
const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
};

// Generate refresh token
const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

// Register a new user
export const Register = async (req, res) => {
    const { name, email, password, confpassword } = req.body;
    const existUser = await Users.findOne({ where: { email } });
    if (existUser) {
        return res.status(400).json({ msg: 'Email is already exist' });
    }
    if (password !== confpassword) {
        return res.status(400).json({ msg: "Password and confirm password do not match" });
    }
    if (!email.includes('@','.')) {
        return res.status(400).json({ msg: 'Please enter valid email' });
    }

    const salt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(password, salt);
    try {
        await Users.create({
            name: name,
            email: email,
            password: hashPassword
        });
        res.json({ msg: "Registration successful" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Internal server error' });
    }
};

// Login function
export const Login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await Users.findOne({ where: { email } });

        if (!user) return res.status(400).json({ msg: 'Email is not registered' });

        //Verify password
        if (!email || !password) {
            return res.status(400).json({ message: "Please provide both email and password" });
        }
        
        try {
            const user = await Users.findOne({ where: { email } });
            const errorMsg = { message: 'Email or password is incorrect' };
        
            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(400).json(errorMsg);
            }
        
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
         

        // Create access token and refresh token
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        // Save refresh token to database
        user.refresh_token = refreshToken; // Assuming there is a refresh_token column in the model
        await user.save();

        // Set secure cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: true, // Set to true if using HTTPS
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000, // 15 minutes
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.json({ accessToken }); // Optionally return tokens in response
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Internal server error' });
    }
};

// Logout function
export const Logout = (req, res) => {
    // Clear the cookies by setting their expiration time to the past
    res.cookie('accessToken', '', {
        httpOnly: true,
        secure: true, // Set to true if using HTTPS
        sameSite: 'Strict',
        expires: new Date(0), // Expire immediately
    });

    res.cookie('refreshToken', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        expires: new Date(0),
    });

    res.status(200).json({ message: 'Logged out successfully' });
};
