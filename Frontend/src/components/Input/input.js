//Nguyen Do Nhat Nam-104061616
import React from "react";

// Functional component for rendering input fields
const Inputs = ({ id, type, name, value, onChange, placeholder }) => {
  return (
    <div className="mb-2 relative m-2">
      {/* Input field */}
      <input
        id={id}
        type={type}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className={`sm:placeholder:text-2xl placeholder:text-xl border-none p-2 md:w-[167px] w-[118px] h-12 rounded-lg bg-gray-200 shadow-xl transition duration-300 focus:bg-gray-200 focus:shadow-inner text-black sm:text-2xl text-xl`}
      />
    </div>
  );
};

export default Inputs;
