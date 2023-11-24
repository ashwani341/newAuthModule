const { app } = require("./app");
const { connectDB } = require("./db/connectDB");
require("dotenv").config();
const { createRolesInDB } = require("./utils/createRolesInDB");

connectDB()
  .then((conn) => {
    console.log("🔆 Database connected to the host:", conn.connection.host);

    app.on("error", (err) => {
      console.log("Error occured while starting the server:\n", err);
    });

    app.listen(process.env.PORT, () => {
      console.log(`🔆 Server is running at ${process.env.PORT}`);
      createRolesInDB();
    });
  })
  .catch((err) => {
    console.log("Error occured while connecting top the database:\n", err);
  });
