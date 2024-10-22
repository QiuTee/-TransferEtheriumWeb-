const checkPassword = (password, retypePassword) => {
  let passwordError = ["", ""];
  const regex = /^(?=.*[!@#$%^&*])(?=.*[A-Z])(?=.*[0-9]).+$/;

  if (!regex.test(password)) {
    passwordError[0] =
      "Password must contain at least one special character, one uppercase letter, and one digit.";
  } else if (password.length < 8) {
    passwordError[0] = "Password must be at least 8 characters";
  } else if (password.length > 20) {
    passwordError[0] = "Password cannot exceed 20 characters";
  } else {
    passwordError[0] = "";
  }

  if (password !== retypePassword) {
    passwordError[1] = "Passwords do not match";
  } else {
    passwordError[1] = "";
  }
  return passwordError;
};
export default checkPassword;
