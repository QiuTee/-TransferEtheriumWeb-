// Tran Thanh Minh - 103809048
import React from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { useBlockChain } from "../../contexts/BlockchainContext";
const DropdownItems = ({ title, route, setShowDropdown }) => {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const { reset } = useBlockChain();
  const handleNavigate = () => {
    if (title === "Sign Out") {
      setShowDropdown(false); // Close the dropdown
      logout(); // Call the logout function from the AuthContext
      reset();
      navigate("/login"); // Navigate to the login page
    } else {
      setShowDropdown(false); // Close the dropdown
      navigate(route); // Navigate to the route
    }
  };
  return (
    <li
      className={`${
        title === "Sign Out"
          ? "bg-red-500 hover:bg-red-800"
          : " hover:bg-slate-600"
      } text-xl sm:text-lg text-center duration-200 ease-in-out p-2 rounded-md hover:border-2 hover:border-slate-950 hover:shadow-lg hover:text-white hover:text-base cursor-pointer`}
      onClick={handleNavigate}
    >
      {title}
    </li>
  );
};

export default DropdownItems;
