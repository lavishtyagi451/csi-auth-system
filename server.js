require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const app = require("./app");

connectDB();

const PORT = process.env.PORT || 5000;

const startServer = () => {
    try {
        app.listen(PORT,() =>{
            console.log(`server is running on port ${PORT}`);
        })
    } catch (error) {
        console.error("Error starting the server:", error.message);
        process.exit(1);
    }

};

startServer();