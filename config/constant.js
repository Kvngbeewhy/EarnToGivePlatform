const SYSTEM_FAILURE = "Internal server error!!!";

const MIDDLEWARE_AUTH_CONSTANTS = {
  ACCESS_DENIED: "Access denied. No authorization token provided",
  RESOURCE_FORBIDDEN: "You don't have access to the request resource.",
  INVALID_AUTH_TOKEN: "Invalid token",
};

const AUTH_CONSTANTS = {
  INVALID_CREDENTIALS: "Invalid email or password",
  INVALID_PASSWORD:
    "You have entered incorrect old password. Please try again with valid password.",
  INACTIVE_ACCOUNT: "Account is not active. please contact admin",
  INVALID_EMAIL:
    "The email provided is not registered. Please sign up to continue.",
  PASSWORD_CHANGE_SUCCESS: "Password changed succesfully",
};
const ADMINLOG_CONSTANT = {
  LOG_CREATED: "Account successfully created.",
  INVALID_ADMINLOG: "Invalid adminlog"
};
const BUSINESSUSER_CONSTANT = {
  INVALID_BUSINESSUSER: "User with given id not found",
  UPDATE_SUCCESS: "User updated successfully",
  SUBMIT_SUCCESS: "User added successfully",
  EMAIL_ALREADY_EXISTS: "Email already registered",
  PHONE_ALREADY_EXISTS: "Phone number already registered",
  INVALID_CACCODE: "Invalid registration number",
  INVALID_CACCERTIFICATE: "Original certificate is require",
  GET_UPDATES: "Approved",
  GET_DATA: "Welcome to api",
  MOBILE_EMAIL_ALREADY_EXISTS: "Mobile and Email both already registered",
  ALL_CHECKS_VALID: "All check are valid",
  VERIFICATION_SUCCESS: "Verification success. Please log in.",
  VERIFICATION_FAILURE:
    "We were unable to find a valid token. Your token may have expired.",
  USER_ALREADY_VERIFIED: "This user has already been verified.",
  VERIFICATION_EMAIL_SENT:
    "Please confirm yourself by clicking on verify user button sent to your email :-)",
  RESET_PASSWORD_EMAIL_SENT: "A reset email has been sent to your email",
  PASSWORD_MISMATCH: "Passwords do not match",
  NOT_YET_VERIFIED: "Your account has not been verified.",
  PASSWORD_CHANGE_SUCCESS: "Password reset successfully!",
};
const PUBLICUSER_CONSTANT = {
  USER_CREATED: "Account successfully created.",
  INVALID_USER: "User with given id not found",
  UPDATE_SUCCESS: "User updated successfully",
  SUBMIT_SUCCESS: "User added successfully",
  EMAIL_ALREADY_EXISTS: "Email already registered",
  PHONE_ALREADY_EXISTS: "Phone number already registered",
  INVALID_CACCODE: "Invalid registration number",
  INVALID_CACCERTIFICATE: "Original certificate is require",
  GET_UPDATES: "Approved",
  GET_DATA: "Welcome to api",
  MOBILE_EMAIL_ALREADY_EXISTS: "Mobile and Email both already registered",
  ALL_CHECKS_VALID: "All check are valid",
  VERIFICATION_SUCCESS: "Verification success. Please log in.",
  VERIFICATION_FAILURE:
    "We were unable to find a valid token. Your token may have expired.",
  USER_ALREADY_VERIFIED: "This user has already been verified.",
  VERIFICATION_EMAIL_SENT:
    "Please confirm yourself by clicking on verify user button sent to your email :-)",
  RESET_PASSWORD_EMAIL_SENT: "A reset email has been sent to your email",
  PASSWORD_MISMATCH: "Passwords do not match",
  NOT_YET_VERIFIED: "Your account has not been verified.",
  PASSWORD_CHANGE_SUCCESS: "Password reset successfully!",
};
const VERSION_CONSTANT = {
  SUBMIT_SUCCESS: "Version details added successfully",
  NO_UPDATE: "You are on latest version",
  VERSION_MANDATORY: "Query parameter v is mandatory",
  APPTYPE_MANDATORY: "Query parameter appType is mandatory",
};

const ADMIN_CONSTANTS = {
  INVALID_EMAIL: "Invalid username/password.",
  BLOCKED_ACCOUNT: "Your account is blocked. Please contact admin.",
};

const TAB_CONSTANTS = {
  SUBMIT_SUCCESS: "Tab added successfully",
  GET_UPDATE: "Successful",
  UPDATE_SUCCESS: "Tab updated successfully",
  NOT_FOUND: "Tab not found",
  TAB_ALREADY_EXISTS: "Tab already exists",
  INVALID_TAB: "Invalid tab"
};
const ITEM_CONSTANTS = {
INVALID_ITEM: "Item not found",
ITEM_CREATED: "Item is created",
ITEM_UPDATED: "Item is Updated",
ITEM_DELETED: "Item is deleted successfully"
};
const BRAND_CONSTANTS = {
  NOT_FOUND: "Brand not found",
  BRAND_CREATED: "Brand is created",
  BRAND_UPDATED: "Brand is created",
  BRAND_DELETED: "Brand is deleted"

};
const CATEGORY_CONSTANTS = {
  NOT_FOUND: "Category not found",
  CATEGORY_CREATED: "Category is succefully created",
  CATEGORY_UPDATED: "Category updated successfully",
  CATEGORY_DELETED: "Category is deleted successfully"
};
const USER_CONSTANTS = {
  INVALID_USER: "User with given id not found",
  UPDATE_SUCCESS: "User updated successfully",
  SUBMIT_SUCCESS: "User added successfully",
  EMAIL_ALREADY_EXISTS: "Email already registered",
  PHONE_ALREADY_EXISTS: "Phone number already registered",
  GET_UPDATES: "Approved",
  GET_DATA: "Welcome to api",
  MOBILE_EMAIL_ALREADY_EXISTS: "Mobile and Email both already registered",
  ALL_CHECKS_VALID: "All check are valid",
  VERIFICATION_SUCCESS: "Verification success. Please log in.",
  VERIFICATION_FAILURE:
    "We were unable to find a valid token. Your token may have expired.",
  USER_ALREADY_VERIFIED: "This user has already been verified.",
  VERIFICATION_EMAIL_SENT:
    "Please confirm yourself by clicking on verify user button sent to your email :-)",
  RESET_PASSWORD_EMAIL_SENT: "A reset email has been sent to your email",
  PASSWORD_MISMATCH: "Passwords do not match",
  NOT_YET_VERIFIED: "Your account has not been verified.",
  PASSWORD_CHANGE_SUCCESS: "Password reset successfully!",
};

module.exports.SYSTEM_FAILURE = SYSTEM_FAILURE;
module.exports.AUTH_CONSTANTS = AUTH_CONSTANTS;
module.exports.MIDDLEWARE_AUTH_CONSTANTS = MIDDLEWARE_AUTH_CONSTANTS; 
module.exports.ADMIN_CONSTANTS = ADMIN_CONSTANTS;
module.exports.VERSION_CONSTANT = VERSION_CONSTANT;
module.exports.TAB_CONSTANTS = TAB_CONSTANTS;
module.exports.USER_CONSTANTS = USER_CONSTANTS;
module.exports.BUSINESSUSER_CONSTANT = BUSINESSUSER_CONSTANT;
module.exports.ITEM_CONSTANTS = ITEM_CONSTANTS;
module.exports.CATEGORY_CONSTANTS = CATEGORY_CONSTANTS;
module.exports.BRAND_CONSTANTS = BRAND_CONSTANTS;
module.exports.PUBLICUSER_CONSTANT = PUBLICUSER_CONSTANT;
module.exports.ADMINLOG_CONSTANT = ADMINLOG_CONSTANT;

