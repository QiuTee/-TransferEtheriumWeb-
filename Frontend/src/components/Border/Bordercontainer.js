//Nguyen Do Nhat Nam-104061616
import React from "react";
const Bordercontainer = ({ children }) => {
  return (
    <div
      className={`
      w-2/3 md:h-96 h-[40rem] flex flex-col items-center justify-center text-center rounded-[50px] border-2 border-white bg-white overflow-hidden
      `}
    >
      {children}
    </div>
  );
};

export default Bordercontainer;
