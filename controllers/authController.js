const User = require("../models/user");
const bcrypt = require("bcryptjs");

const generateOTP = require("../utils/generateOTP");
const sendEmail = require("../utils/sendEmail");

const {generateAccessToken,generateRefreshToken} = require("../utils/generateTokens");

const crypto = require("crypto");

// Register a new user
const registerUser = async (req, res) => {
    try {

        const { name, email, password } = req.body;

    
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, email and password are required"
            });
        }

    
        const normalizedEmail = email.trim().toLowerCase();

        
        const existingUser = await User.findOne({
            email: normalizedEmail
        });


        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "Email is already registered"
            });
        }

    
        const passwordHash = await bcrypt.hash(password, 12);

        
        const otp = generateOTP();
        const otpHash = await bcrypt.hash(otp, 10);

        //  Creating the user
        const user = await User.create({
            name: name.trim(),
            email: normalizedEmail,
            passwordHash: passwordHash,
            isVerified: false,
            otpHash: otpHash,
            otpExpiryAt: new Date(Date.now() + 5 * 60 * 1000),
            otpAttempts: 0,
            otpResendCount: 0
        });

        
        try {
            await sendEmail(
                normalizedEmail,
                "Verify your email",
                `Your OTP is ${otp}. It expires in 5 minutes.`);
        } catch (emailError) {
            // Remove account if email delivery fails
            await User.deleteOne({ _id: user._id });

            throw emailError;
        }
           return res.status(201).json({
            success: true,
            message: "Registration successful. Please verify your email."
        });

    } catch (error) {
        console.error("Registration error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Something went wrong during registration"
        });
    }
};



const verifyOTP = async (req, res) => {
    try {

        const { email, otp } = req.body;

    
        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: "Email and OTP are required"
            });
        }

        
        const normalizedEmail = email.trim().toLowerCase();

        // find user then fetching hidden OTP details
        const user = await User.findOne({email: normalizedEmail}).select("+otpHash +otpExpiryAt +otpAttempts");

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }


        if (user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "Email is already verified"
            });
        }

        // Checking otp existence & expiry
        if (!user.otpHash || !user.otpExpiryAt ||
            user.otpExpiryAt.getTime() <= Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP is missing or expired. Please request a new OTP."
            });
        }

    
        if (user.otpAttempts >= 3) {
            return res.status(429).json({
                success: false,
                message: "Too many incorrect attempts. Request a new OTP."
            });
        }

        
        const isOTPValid = await bcrypt.compare(
            String(otp),
            user.otpHash
        );

        if (!isOTPValid) {
            user.otpAttempts += 1;
            await user.save();

            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            });
        }

        // mark user as verified and invalidate OTP
        user.isVerified = true;
        user.otpHash = undefined;
        user.otpExpiryAt = undefined;
        user.otpAttempts = 0;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Email verified successfully. You can now log in."
        });

    } catch (error) {
        console.error("OTP verification error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Something went wrong during OTP verification"
        });
    }
};

// Resend OTP
const resendOTP = async (req, res) => {
    try {
        const email = req.body.email;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const user = await User.findOne({
            email: normalizedEmail
        }).select("+otpHash +otpExpiryAt +otpResendCount");

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "Email is already verified"
            });
        }

        if (user.otpResendCount >= 3) {
            return res.status(429).json({
                message: "Maximum number of OTP resend attempts reached."
            });
        }

        const otp = generateOTP();
        const otpHash = await bcrypt.hash(otp, 10);

        user.otpHash = otpHash;
        user.otpExpiryAt = new Date(Date.now() + 5 * 60 * 1000);
        user.otpAttempts = 0;
        user.otpResendCount += 1;

        await user.save();

        try {
            await sendEmail(
                normalizedEmail,
                "Verify your email",
                `Your new OTP is ${otp}. It expires in 5 minutes.`
            );
        } catch (emailError) {
            console.error("OTP resend email error:", emailError.message);
            return res.status(500).json({
                success: false,
                message: "Failed to send OTP email"
            });
        }

        return res.status(200).json({
            success: true,
            message: "A new OTP has been sent to your email."
        });
    } catch (error) {
        console.error("OTP resend error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Something went wrong while resending OTP"
        });
    }
};

const loginUser = async (req, res) => {
    try {
        
        const { email, password } = req.body;

        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        
         const normalizedEmail = email.trim().toLowerCase();

        
        const user = await User.findOne({
            email: normalizedEmail
        }).select("+passwordHash");

           //  Reject if user doesn't exist /password incorrect
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

    
        if (!user.isVerified) {
            return res.status(403).json({
                success: false,
                message: "Please verify your email before logging in"
            });
        }

        // generate a unique session ID
        const sessionId = crypto.randomUUID();

    
        const accessToken = generateAccessToken(user._id);

        const refreshToken = generateRefreshToken(
            user._id,
            sessionId
        );

    
        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        //  Saving refreshtoken session details
        user.refreshTokenHash = refreshTokenHash;
        user.refreshTokenSessionId = sessionId;

        await user.save();

        
        return res.status(200).json({
            success: true,
            message: "Login successful",
            accessToken,
            refreshToken,
            tokenType: "Bearer",
            expiresIn: 900
        });

    } catch (error) {
        console.error("Login error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

module.exports = {
    registerUser,
    verifyOTP,
    resendOTP,
    loginUser
};