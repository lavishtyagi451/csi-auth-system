const express = require("express");

const app = express();

// Middleware to parse JSON requests
app.use(express.json());

app.get("/", (req, res) => {
    res.status(200).json({ message: "Welcome to the CSI Auth System API" });
});

app.get("/api/health", (req, res) => {
    res.status(200).json({ message: "Backend is healthy" });
});


module.exports = app;