import React from "react";
import { NavLink } from "react-router-dom";
const NavbarItem = ({ children, to }) => {
  return (
    <NavLink to={to}>
      {({ isActive }) => (
        <div
          className={
            isActive
              ? "underline underline-offset-4 hover:underline-offset-8 decoration-sky-500ml-4 ml-4 mr-4 border-2 border-transparent hover:border-white duration-300 ease-out p-2 rounded-md hover:bg-slate-100/10"
              : "ml-4 mr-4 border-2 border-transparent hover:border-white duration-300 ease-out p-2 rounded-md hover:bg-slate-100/10"
          }
        >
          {children}
        </div>
      )}
    </NavLink>
  );
};

export default NavbarItem;
