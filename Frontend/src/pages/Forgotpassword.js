import React, { useState } from "react";
import Signupbutton from "../components/Button/Signupbutton";
import { ToastContainer, toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import "react-toastify/dist/ReactToastify.css";
import LoadingContainer from "../components/LoadingContainer";
import submission from "../utils/submission";
import handleResponse from "../utils/handleResponse";

const Forgotpassword = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    email: "",
  });

  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await submission(
        "change/forget_password/",
        "post",
        formData
      );
      if (response.error) {
        toast.error(handleResponse(response.error), { toastId: "toast" });
      } else if (response.status === "200 OK") {
        toast.success(
          `${
            response.message ? response.message : "Password reset email sent"
          }`,
          { toastId: "toast" }
        );
        setTimeout(() => {
          navigate("/changepw");
        }, 3000);
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
    <div className="w-auto overflow-hidden flex flex-col">
      <h2 className="flex font-bold justify-center sm:text-4xl text-2xl text-white mt-32 pb-8">
        We will send you a link via your email !
      </h2>

      <form onSubmit={handleSubmit} className="flex flex-col">
        <div className="flex justify-center text-2xl text-white m-5">
          <img
            src="/images/icon/person.png"
            alt="icon of username"
            className="h-14 w-14 mr-4"
          />
          <input
            type="text"
            id="username"
            name="username"
            placeholder="Enter your username"
            onChange={handleChange}
            required
            className="text-black rounded-lg h-15 w-50 bg-white-500 p-2"
          />
        </div>
        <div className="flex justify-center text-2xl text-white m-5">
          <img
            src="/images/icon/mail.png"
            alt="icon of username"
            className="h-14 w-14 mr-4"
          />
          <input
            type="text"
            id="email"
            name="email"
            placeholder="Enter your email"
            onChange={handleChange}
            required
            className="text-black rounded-lg h-15 w-50 bg-white-500 p-2"
          />
        </div>
        <div className="mt-[35px] flex justify-center items-center h-full text-3xl">
          {loading ? (
            <LoadingContainer />
          ) : (
            <Signupbutton type="submit">Receive Link</Signupbutton>
          )}
        </div>
      </form>

      <ToastContainer
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover={false}
        theme="dark"
      />
    </div>
  );
};

export default Forgotpassword;
