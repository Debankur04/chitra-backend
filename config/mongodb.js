const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        console.log("✅ Database Connected");

        // Event listeners after successful connection
        mongoose.connection.on('error', (err) => {
            console.error("❌ MongoDB Connection Error:", err);
        });

    } catch (error) {
        console.error("❌ Database Connection Failed:", error.message);
        process.exit(1);
    }
};

module.exports = connectDB;