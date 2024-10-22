import React, { useState, useEffect } from "react";
import Signupbutton from "../components/Button/Signupbutton";
import { LoginData } from "../data/LoginData";
import { useAuth } from "../contexts/AuthContext";
import { ToastContainer, toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import "react-toastify/dist/ReactToastify.css";
import LoadingContainer from "../components/LoadingContainer";
import { Link } from "react-router-dom";

const Login = () => {
  const { login, isAuthenticated } = useAuth();
  // Navigation hook
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
  });
  const [isHovered, setIsHovered] = useState(false);

  const handleMouseEnter = () => {
    setIsHovered(true);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
  };

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
      // Wait for the login function to complete
      const result = await login(formData);
      // Show success toast
      if (!isAuthenticated && result === undefined) {
        toast.error("Invalid email or password", { toastId: "toast" });
      }
    } catch (error) {
      toast.error(error.message, { toastId: "toast" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      const successToastId = toast.success("Login Successfully", {
        autoClose: 1000,
        toastId: "toast",
      });

      const timer = setTimeout(() => {
        navigate("/transaction");
      }, 1000);

      return () => {
        clearTimeout(timer);
        toast.dismiss(successToastId);
      };
    }
  }, [isAuthenticated, navigate]);

  return (
    <div className="w-auto overflow-hidden flex flex-col">
      <h2 className="flex font-bold justify-center text-4xl text-white mt-32 pb-12">
        Login
      </h2>

      <form onSubmit={handleSubmit} className="flex flex-col">
        {LoginData.map(({ src, alt, type, id, placeholder }) => (
          <div className="flex justify-center text-2xl text-white m-5" key={id}>
            <img src={src} alt={alt} className="h-14 w-14 mr-4" />
            <input
              type={type}
              id={id}
              name={id}
              placeholder={placeholder}
              onChange={handleChange}
              required
              className="text-black rounded-lg h-15 w-50 bg-white-500 p-2"
            />
          </div>
        ))}
        <div className="ml-56">
          <Link
            to="/forgotpw"
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            style={{ color: isHovered ? "purple" : "white" }}
          >
            Forgot Password?
          </Link>
        </div>
        <div className="mt-[35px] flex justify-center items-center h-full text-3xl">
          {loading ? (
            <LoadingContainer />
          ) : (
            <Signupbutton type="submit">Login</Signupbutton>
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

export default Login;
