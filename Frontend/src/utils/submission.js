import AxiosInstance from "./Axios";

const submission = async (route, method = "post", data = {}) => {
  console.log("Sent Data", data);
  try {
    const response = await AxiosInstance({
      method: method.toLowerCase(),
      url: route,
      data: data,
    });
    // console.log("Response from server:", response.data);
    return response.data; // You can return the response data if needed
  } catch (error) {
    console.log("Error:", error);
    throw error;
  }
};

export default submission;
