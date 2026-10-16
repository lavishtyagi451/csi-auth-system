const express = require("express");
const app = express();

// Authentication routes
const authRoutes = require("./routes/authRoutes");


app.use(express.json());

app.use("/api/auth", authRoutes);


app.get("/", (req, res) => {
    res.status(200).json({
        message: "Welcome to the CSI Auth System API"
    });
    
});


app.get("/api/health", (req, res) => {
    res.status(200).json({
        message: "Backend is healthy"
    });
});

module.exports = app;