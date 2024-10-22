//Nguyen Do Nhat Nam-104061616
import React from "react";
import Bordercontainer from "./Bordercontainer.js";
import Logo from "./Logo.js";
import { BorderData } from "../../data";

const Bordermain = () => {
  return (
    <>
      <Bordercontainer>
        <h1 className="text-black font-bold sm:text-5xl text-4xl sm:pt-0 pt-7">
          Our Service
        </h1>
        <div className="flex md:flex-row flex-col items-center justify-center w-full">
          {BorderData.map(({ image, alt, title }) => (
            // Each service item is wrapped in a fragment to avoid unnecessary divs
            <div
              key={title}
              className="basis-1/2 sm:w-full sm:mx-12 flex flex-col items-center justify-center border-white border-4 hover:border-black duration-300 ease-in rounded-[60px] py-12 mx-4 my-4 p-4"
            >
              {/* Logo component is used to display the image */}
              <Logo>
                <img src={image} alt={alt} />
              </Logo>
              {/* Title of the service */}
              <h2 className="text-black sm:text-3xl text-2xl font-bold">
                {title}
              </h2>
            </div>
          ))}
        </div>
      </Bordercontainer>
    </>
  );
};

export default Bordermain;
