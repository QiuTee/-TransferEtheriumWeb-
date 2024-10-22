//Nguyen Do Nhat Nam
import React from "react";
import { FiSend } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
const Homebutton = ({ children, icon }) => {
  const navigate = useNavigate();
  return (
    <div className="justify-center flex items-center sm:justify-center md:justify-start">
      {/* Button Component */}
      <button
        onClick={() => navigate("/transaction")}
        className={`w-48 h-12 justify-center text-xl mt-8 mx-4
          px-4 py-2 rounded-full 
          flex items-center gap-2 
          text-slate-400
          shadow-[-5px_-5px_10px_rgba(255,_255,_255,_0.8),_5px_5px_10px_rgba(0,_0,_0,_0.25)]

          transition-all

          hover:shadow-[-1px_-1px_5px_rgba(255,_255,_255,_0.6),_1px_1px_5px_rgba(0,_0,_0,_0.3),inset_-2px_-2px_5px_rgba(255,_255,_255,_1),inset_2px_2px_4px_rgba(0,_0,_0,_0.3)]
          hover:text-white
      `}
      >
        {/* Icon (default is FiSend if no icon is provided) */}
        {icon ? icon : <FiSend />}
        {/* Button Text/Content */}
        <span>{children}</span>
      </button>
    </div>
  );
};

export default Homebutton;
