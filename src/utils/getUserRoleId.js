const Role = require("../models/Role.model");
const { ROLES } = require("../constants/constants");

async function getUserRoleId() {
  try {
    const roles = await Role.find();
    const userRole = roles.filter((role) => role.name === ROLES.user);
    if (!userRole.length) throw new Error("No roles found in database.");

    return userRole[0].id;
  } catch (error) {
    console.log(error.message);
    return;
  }
}

module.exports = getUserRoleId;
