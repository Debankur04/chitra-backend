const jwt = require('jsonwebtoken');

module.exports.userAuth = async (req, res, next) => {
    try {
        // Extract token from Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.json({ success: false, message: 'Not Authorized. Login Again' });
        }

        const token = authHeader.split(' ')[1]; // Extract the actual token

        // Verify token
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (!tokenDecode.id) {
            return res.json({ success: false, message: 'Not Authorized. Login Again' });
        }

        req.body.userId = tokenDecode.id; // Attach user ID to request
        next(); // Proceed to next middleware

    } catch (error) {
        return res.json({ success: false, message: 'Invalid Token. Login Again' });
    }
};
