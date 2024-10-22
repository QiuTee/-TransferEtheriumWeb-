const handleResponse = (response, page = "") => {
  if (response === "Network Error") {
    return "We're currently facing connectivity issues. Please try again later.";
  } else if (response === "Failed to fetch") {
    return "We're currently facing connectivity issues. Please try again later.";
  } else if (response === "Request failed with status code 401") {
    return "Unauthorized";
  } else if (response === "Request failed with status code 404") {
    return "Page Not Found";
  } else if (response === "Request failed with status code 500") {
    return "Internal Server Error";
  } else if (response === "Request failed with status code 400") {
    return "Bad Request";
  } else if (response === "Request failed with status code 403") {
    return "Forbidden";
  }
  return response;
};
export default handleResponse;
