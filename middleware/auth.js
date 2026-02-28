import jwt from 'jsonwebtoken';

//=================================== TOKEN VERIFICATION MIDDLEWARE ===========================================
export const verifyToken = (req, res, next) => {
    console.log("verifyToken middleware hit");
    
    const token = req.headers['authorization']?.split(' ')[1] || req.cookies.token;
    if (!token) {
        console.log("No token provided by user");
        return res.status(403).json({ error: "No token provided" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log("Token verification failed");
            return res.status(401).json({ error: "Unauthorized" });
        }
        req.user = decoded;
        console.log("Token verified successfully for user:", req.user.id);
        next();
    });
};

//=================================== ADMIN ROLE VERIFICATION ===========================================
export const isAdmin = (req, res, next) => {
    console.log("isAdmin middleware hit");
    
    if (req.user && req.user.role === 'admin') {
        console.log("Admin access granted");
        next();
    } else {
        console.log("Admin access denied - User is not an admin");
        res.status(403).json({ error: "Requires Admin Role" });
    }
};