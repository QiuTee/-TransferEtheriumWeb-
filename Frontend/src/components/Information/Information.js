//Nguyen Do Nhat Nam-104061616
import React from "react";
import Homebutton from "../Button/Homebutton";
import { Description } from "../../data";

// Functional component for rendering information section
const Information = () => {
  return (
    <div className="flex md:flex-row flex-col items-center justify-center mt-24 w-auto overflow-hidden">
      {/* Left Section */}
      <div className="basis-1/2 mx-8">
        <h2 className="font-bold sm:text-4xl text-3xl">Web3 Technology</h2>
        <h3 className="sm:text-2xl text-xl text-slate-400 my-4">
          Immerse yourself in the transformative power of Web3, reshaping the
          way we interact with the digital world through decentralized
          technologies and enhanced security
        </h3>
        {/* Home Button */}
        <Homebutton>Get Started</Homebutton>
      </div>

      {/* Right Section */}
      <div className="basis-1/2 mx-8 m-8">
        {/* Render items from Description data */}
        {Description.map(({ main, text, image, alt }) => (
          <li
            className="group my-2 flex flex-center p-2 border-black border-4 hover:bg-slate-800 hover:border-slate-800 duration-300 ease-in rounded-[20px]"
            key={main}
          >
            <div className="mx-4">
              {/* Image */}
              <img
                className="group-hover:rotate-3 group-hover:scale-150 h-15 w-20 mr-2 mt-2 relative transition-transform duration-300 transform hover:rotate-3 hover:scale-150"
                src={image}
                alt={alt}
              />
            </div>
            <div>
              {/* Heading */}
              <h3 className="sm:text-3xl text-2xl">{main}</h3>
              {/* Text */}
              <p className="sm:text-2xl text-xl text-slate-400">{text}</p>
            </div>
          </li>
        ))}
      </div>
    </div>
  );
};

export default Information;
