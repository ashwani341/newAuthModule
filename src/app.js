const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const configureCors = require("./configs/corsConfig");
const userRouter = require('./routes/user.routes')

const app = express();

//#region middleware setup ####################################################################################################
app.use(cors());
// configureCors(app);

app.use(morgan("common"));

app.use(
  express.json({
    // limit: '512kb'   //limit on recieving data to avoid server crash
  })
);

app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(express.static("public")); //Location of static files to be servered from the server
//#endregion middleware setup #################################################################################################

app.use('/api/v1/users', userRouter)

//= To ping the api  ====================================================================================================
app.get("/test", (req, res) => {
  return res.status(200).json({ message: "Working!" });
});

module.exports = { app };
