const express = require("express");
const router = express.Router();

const {registerUser,
    verifyOTP,
    resendOTP,
    loginUser,
    refreshAccessToken,
    logoutUser} = require("../controllers/authController");

router.post("/register", registerUser);
router.post("/verify-otp", verifyOTP);
router.post("/resend-otp", resendOTP);
router.post("/login", loginUser);
router.post("/refresh-token", refreshAccessToken);
router.post("/logout", logoutUser);


module.exports = router;