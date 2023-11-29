require("dotenv").config();
const { connectDB } = require("./db/connectDB");
const { app } = require("./app");
const { createRolesInDB } = require("./utils/createRolesInDB");

connectDB()
  .then((conn) => {
    console.log("🔆 Database connected to the host:", conn.connection.host);

    app.on("error", (err) => {
      console.log("Error occured while starting the server:\n", err);
    });

    app.listen(process.env.PORT, async () => {
      await createRolesInDB();
      console.log(`🔆 Server is running at ${process.env.PORT}`);
    });
  })
  .catch((err) => {
    console.log("Error occured while connecting top the database:\n", err);
  });
