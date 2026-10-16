require("dotenv").config();

const sendEmail = require("./utils/sendEmail");

const testEmail = async () => {
    try {
        await sendEmail(
            process.env.EMAIL_USER,
            "CSI Authentication - Email Test",
            "If you received this email, Nodemailer is working correctly."
        );

        console.log("Email sent successfully");
    } catch (error) {
        console.error("Email sending failed:", error.message);
    }
};

testEmail();