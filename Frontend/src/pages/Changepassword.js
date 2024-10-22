//Nguyen Do Nhat Nam-104061616
import React, { useState } from "react";
import Input from "../components/Input/index.js";
import Signupbutton from "../components/Button/Signupbutton.js";
import { useNavigate } from "react-router-dom";
import { ToastContainer, toast } from "react-toastify";
import submission from "../utils/submission.js";
import checkPassword from "../utils/checkPassword.js";
import LoadingContainer from "../components/LoadingContainer";
import handleResponse from "../utils/handleResponse.js";

export default function Changepassword() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    otp: "",
    password: "",
    confirm_password: "",
  });
  const [error, setError] = useState({
    otp: "",
    password: "",
    confirm_password: "",
  });

  const [loading, setLoading] = useState(false);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData((prevState) => ({ ...prevState, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);

    // Validate password, confirm_password, and otp
    const [passwordError, confirm_passwordError] = checkPassword(
      formData.password,
      formData.confirm_password
    );
    setError((prevState) => ({
      ...prevState,
      password: passwordError,
      confirm_password: confirm_passwordError,
    }));

    try {
      // Check for any validation errors
      if (passwordError[0] || confirm_passwordError[1]) {
        throw new Error("Please fix the errors in the form.");
      }
      // Submit the form data
      const response = await submission(
        "change/reset_password/",
        "put",
        formData
      );

      if (response.error) {
        toast.error(response.error, { toastId: "toast" });
      } else if (response.status === "200 OK" && response.message) {
        toast.success(response.message, { toastId: "toast" });
        setTimeout(() => {
          navigate("/login");
        }, 2000);
      } else if (response.status === "200 OK") {
        toast.success(
          `${
            response.message
              ? response.message
              : "Password changed successfully."
          }`,
          {
            toastId: "toast",
          }
        );
        setTimeout(() => {
          navigate("/login");
        }, 2000);
      } else {
        toast.error(
          handleResponse(
            `${
              response.message
                ? response.message
                : "Something went wrong. Please try again later"
            }`
          ),
          { toastId: "toast" }
        );
      }
    } catch (error) {
      console.log(error.message);
      toast.error(handleResponse(error.message), { toastId: "toast" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="bg-black overflow-hidden text-white flex justify-center items-center mx-auto">
        <div className="">
          {/* Change Password Header */}
          <h1 className="text-center mb-4 text-[40px]">
            <strong>Change Password</strong>
          </h1>

          {/* Form */}
          <form onSubmit={handleSubmit} className="flex flex-col ">
            {/* Pin Number Input */}
            <div className="flex flex-row justify-center items-center mt-2">
              <img
                src="./images/icon/lock.png"
                alt="lock"
                className="h-14 w-14 mt-2 mr-1"
              />
              <Input
                id="pin-number"
                label="Pin Number"
                type="text"
                name="otp"
                value={formData.otp}
                onChange={handleChange}
                placeholder="Pin Number"
              />
            </div>

            {/* Password Input */}
            <div className="flex flex-row justify-center items-center ">
              <img
                src="./images/icon/lock.png"
                alt="lock"
                className="h-14 w-14 mt-2 mr-1"
              />
              <Input
                id="password"
                label="New Password"
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="New Password"
              />
            </div>

            {/* Retype Password Input */}
            <div className="flex flex-row justify-center items-center mt-2">
              <img
                src="./images/icon/lock.png"
                alt="lock"
                className="h-14 w-14 mt-2 mr-1"
              />
              <Input
                id="confirm_password"
                label="Retype New Password"
                type="password"
                name="confirm_password"
                value={formData.confirm_password}
                onChange={handleChange}
                placeholder="Retype New Password"
              />
            </div>

            {/* Error Messages */}
            {error.otp && (
              <div className="w-3/4 text-red-500 self-center text-center text-wrap">
                {error.otp}
              </div>
            )}
            {error.password && (
              <div className="w-3/4 text-red-500 self-center text-center text-wrap">
                {error.password}
              </div>
            )}
            {error.confirm_password && (
              <div className="w-3/4 text-red-500 self-center text-center text-wrap">
                {error.confirm_password}
              </div>
            )}

            {/* Change Password Button */}
            <div className="mt-[35px] flex justify-center items-center h-full">
              {loading ? (
                <LoadingContainer />
              ) : (
                <Signupbutton type="submit" className="m-5">
                  Change Password
                </Signupbutton>
              )}
            </div>
          </form>
        </div>
      </div>{" "}
      <ToastContainer
        position="top-right"
        autoClose={2000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover={false}
        theme="dark"
      />
    </>
  );
}
