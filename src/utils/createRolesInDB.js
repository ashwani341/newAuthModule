const Role = require("../models/Role.model");
const { ROLES } = require("../constants/constants");

async function createRolesInDB() {
  try {
    const roles = await Role.find();

    if (!roles.length) {
      for (let key in ROLES) {
        if (ROLES.hasOwnProperty(key)) {
          const rolesCreated = await Role.create({ name: ROLES[key] });

          if (!rolesCreated)
            throw new Error(
              "Error occured while inserting roles in the database."
            );
        }
      }
      console.log("🔆 Roles inserted in the database successfully.");
    }
  } catch (error) {
    console.log("Error: \n", error);
  }
}

module.exports = {
  createRolesInDB,
};
