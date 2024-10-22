// Tran Thanh Minh - 103809048
import React from "react";
import DropdownItems from "./DropdownItems"; // Import the DropdownItems component
const MenuItems = [
  { route: "/settings", title: "Settings" },
  { route: "/history", title: "History" },
  { route: "/", title: "Sign Out" },
];
// Define the DropdownMenu component
const DropdownMenu = ({ setShowDropdown }) => {
  return (
    <div className="top-[12rem] right-[10.5rem] flex flex-col absolute md:top-[5.5rem] md:right-[1.5rem] w-[150px] p-[15px] rounded-[15px] bg-white border border-cyan z-10 overflow-hidden">
      <ul className="flex flex-col gap-4 font-normal text-black text-lg whitespace-nowrap">
        {MenuItems.map((item) => (
          <DropdownItems
            key={item.title}
            route={item.route}
            title={item.title}
            setShowDropdown={setShowDropdown}
          />
        ))}
      </ul>
    </div>
  );
};

export default DropdownMenu;
