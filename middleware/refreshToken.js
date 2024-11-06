import jwt from 'jsonwebtoken';
import Users from '../models/UserModel.js';

export const verifyRefreshToken = async (req, res, next) => {
    const token = req.headers['x-refresh-token'];
    if (!token) return res.sendStatus(401); // Jika tidak ada refresh token

    try {
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET); // Ganti dengan secret yang sesuai
        const user = await Users.findOne({ where: { id: decoded.id } });

        if (!user || user.refresh_token !== token) {
            return res.sendStatus(403); // Token tidak valid
        }

        req.user = user; // Simpan informasi pengguna
        next(); // Lanjutkan ke middleware berikutnya
    } catch (error) {
        return res.sendStatus(403); // Token tidak valid
    }
};
