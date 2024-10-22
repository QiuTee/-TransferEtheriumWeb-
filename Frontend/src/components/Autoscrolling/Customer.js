//Nguyen Do Nhat Nam-104061616
import React from "react";
import Marquee from "react-fast-marquee";
import Row1 from "./Row1";
import Row2 from "./Row2";
import Row3 from "./Row3";

const Customer = () => {
  return (
    <div className="w-full min-h-screen flex flex-col justify-center items-center bg-black text-neutral-200">
      <div className="w-[100%] flex flex-col">
        {/* Heading */}
        <div className="flex space-y-2 flex-col text-center mb-14">
          <span className="text-5xl font-bold">Our Customers</span>
        </div>

        {/* Scrolling Marquee for Row1 */}
        <Marquee
          speed={100}
          autoFill={true}
          pauseOnClick
          gradient
          gradientColor="black"
        >
          <div className="h-[250px] m-1 rounded-xl flex space-x-5 cursor-pointer text-white">
            <Row1 />
          </div>
        </Marquee>

        {/* Scrolling Marquee for Row2 */}
        <Marquee
          speed={180}
          autoFill={true}
          pauseOnClick
          gradient
          gradientColor="black"
          direction="right"
        >
          <div className="h-[250px] m-1 rounded-xl flex space-x-5 cursor-pointer text-white">
            <Row2 />
          </div>
        </Marquee>

        {/* Scrolling Marquee for Row3 */}
        <Marquee
          speed={150}
          autoFill={true}
          pauseOnClick
          gradient
          gradientColor="black"
        >
          <div className="h-[250px] m-1 rounded-xl flex space-x-5 cursor-pointer text-white">
            <Row3 />
          </div>
        </Marquee>
      </div>
    </div>
  );
};

export default Customer;
