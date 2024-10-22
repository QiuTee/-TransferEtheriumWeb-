// Tran Thanh Minh - 103809048
import React from "react";
import { useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import NavbarItem from "./NavbarItem";
import DropdownMenu from "./DropdownMenu";
import Avatar from "@mui/material/Avatar";
import Stack from "@mui/material/Stack";
import StringAvatar from "../../utils/StringAvatar";
import { useNavigate } from "react-router-dom";
const Navbar = () => {
  const { user, isAuthenticated } = useAuth(); // Get the user and isAuthenticated from the AuthContext
  const [showDropdown, setShowDropdown] = useState(false); // State to control the dropdown
  const navigate = useNavigate(); // Get the navigate function from React Router
  return (
    <div className="flex flex-col md:flex-row md:items-start items-center justify-between w-auto overflow-hidden">
      <div className="basis-1/2 flex items-center md:justify-start justify-center md">
        <img
          src="./logo.png"
          className="md:ml-[-25px] md:mt-[-25px] w-1/2 sm:w-1/2 md:w-4/5 lg:ml-[-25px] lg:mt-[-25px] lg:w-1/2 cursor-pointer"
          alt="Logo of DigiCode"
          onClick={() => navigate("/")} // Navigate to the home page
        />
      </div>
      <div className="flex flex-row text-2xl lg:text-3xl p-4 basis-1/2 justify-end md:mt-2 lg:mt-4 h-full">
        <div className="flex flex-row justify-between">
          {!isAuthenticated ? (
            <NavbarItem to="/">Home</NavbarItem>
          ) : (
            <NavbarItem to="/transaction">Transaction</NavbarItem>
          )}
          <NavbarItem to="/block">Block</NavbarItem>

          <div className="text-4xl">|</div>
          {!isAuthenticated ? (
            <div className="flex flex-row justify-between whitespace-nowrap">
              <NavbarItem to="/login">Log In</NavbarItem>
              <NavbarItem to="/signup">Sign Up</NavbarItem>
            </div>
          ) : (
            <>
              <div
                className="cursor-pointer hover:underline hover:underline-offset-4 mt-2 mx-4 whitespace-nowrap text-xl md:text-2xl"
                onClick={() => setShowDropdown(!showDropdown)}
              >
                <Stack direction="row" spacing={2}>
                  <Avatar {...StringAvatar(user.name)} />
                  <span>{user.name}</span>
                </Stack>
              </div>
              {showDropdown && (
                <DropdownMenu setShowDropdown={setShowDropdown} />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Navbar;
