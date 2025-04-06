const jwt = require('jsonwebtoken');

module.exports.userAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.json({ success: false, message: 'Not Authorized. Login Again' });
        }

        const token = authHeader.split(' ')[1];
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (!tokenDecode.id) {
            return res.json({ success: false, message: 'Not Authorized. Login Again' });
        }

        req.userId = tokenDecode.id; // ✅ safer than req.body.userId
        next();

    } catch (error) {
        return res.json({ success: false, message: 'Invalid Token. Login Again' });
    }
};
