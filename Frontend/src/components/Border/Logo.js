//Nguyen Do Nhat Nam-104061616
import React from "react";

const Logo = ({ children }) => {
  return (
    <div
      className={`
        w-20
        h-20
        border-10
        border-black
        border-radius-4
      `}
    >
      {children}
    </div>
  );
};

export default Logo;
