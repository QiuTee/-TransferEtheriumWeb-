const checkEmail = (value) => {
  let emailError = "";
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;

  if (!emailRegex.test(value)) {
    emailError = "Invalid email format. Please include the @ symbol.";
  } else if (value === "") {
    emailError = "Please enter an email address.";
  } else {
    emailError = "";
  }

  return emailError;
};

export default checkEmail;
