const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
    try{
        const authHeader = req.headers.authorization;

        if(!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success:false,
                message: "Access token is required"
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET,
            {
                algorithms: ["HS256"],
                issuer: "csi_auth-system",
                audience: "csi-auth-client"

            }
        );

        if(decoded.tokenType != "access") {
            return res.status(401).json({
                success: false,
                message: "Invalid or expired access token"
            });
        }
        req.user = {
            id: decoded.sub
        };
        next();
    } catch(error) {
        return res.status(401).json({
        success: false,
        message: "Invalid or expired access token"
        });

}

};
 module.exports = authMiddleware;
 