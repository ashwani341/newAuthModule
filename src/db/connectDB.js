const { default: mongoose } = require("mongoose");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      dbName: process.env.DB_NAME,
    });
    // console.log("Database connected to the host:", conn.connection.host);
    return conn;
  } catch (error) {
    throw error;
  }
};

module.exports = { connectDB };
