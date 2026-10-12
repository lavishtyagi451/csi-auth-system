const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },

        passwordHash: {
            type: String,
            required: true,
            select: false                                          

        },

        isVerified: {
            type: Boolean,
            default: false
    },

        otpHash: {
            type: String,
            select: false
        },

        otpExpiryAt: {
            type: Date,
            select: false
        },

        otpAttempts: {
            type: Number,
            default: 0,
            select: false
        },


        refreshTokenHash: {
            type: String,
            select: false
        }

    },
    { timestamps: true }
);

const User = mongoose.model("User", userSchema);

module.exports = User;