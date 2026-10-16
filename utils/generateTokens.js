const jwt = require("jsonwebtoken");

const generateAccessToken = (userId) => {
    return jwt.sign(
        {
            sub: userId.toString(),
            tokenType: "access"
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            algorithm: "HS256",
            expiresIn: "15m",
            issuer: "csi-auth-system",
             audience: "csi-auth-client"

        }
    );
};


const generateRefreshToken = (userId,sessionId) =>{
    return jwt.sign(
        {
            sub: userId.toString(),
            sid: sessionId,
            tokenType: "refresh"
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            algorithm: "HS256",
            expiresIn: "7d",
            issuer: "csi-auth-system",
             audience: "csi-auth-client"
        }
    );
};

module.exports = {
    generateAccessToken,generateRefreshToken
};