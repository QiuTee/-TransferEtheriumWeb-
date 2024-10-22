import React from "react";
import "./Verifybutton.css";
const Verifybutton = ({ handleSubmit }) => {
  return (
    <button
      className="btn text-white font-bold py-2 px-4 rounded"
      onClick={() => handleSubmit()}
    >
      Verify OTP
    </button>
  );
};

export default Verifybutton;
