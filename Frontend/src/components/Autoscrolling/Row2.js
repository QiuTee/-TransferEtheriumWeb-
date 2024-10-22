//Nguyen Do Nhat Nam-104061616
import React from "react";
import { People } from "../../data";

const Row2 = () => {
  return (
    <>
      {/* Mapping through the second set of people data */}
      {People[1].map(({ image, name, position, feedback, alt }) => (
        // Using a fragment to avoid unnecessary divs
        <div
          key={name}
          className="bg-slate-900 rounded-md mx-2 flex flex-row items-center justify-center p-4 w-[700px] h-[250px]"
        >
          {/* Displaying the person's image */}
          <div className="w-[100px] basis-1/3 flex items-center justify-center">
            <img
              className="w-2/3 h-[250px] object-contain"
              src={image}
              alt={alt}
            />
          </div>
          {/* Displaying the person's details */}
          <div className="basis-2/3 flex flex-col">
            <h2 className="text-3xl font-bold">{name}</h2>
            <h3 className="text-2xl font-bold my-2">{position}</h3>
            <p className="text-xl text-slate-400">{feedback}</p>
          </div>
        </div>
      ))}
    </>
  );
};

export default Row2;
