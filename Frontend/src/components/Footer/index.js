// Tran Thanh Minh - 103809048
import React from "react";
import { FooterInfo } from "../../data";
import FooterTitle from "./FooterTitle";
import FooterContainer from "./FooterContainer";
const index = () => {
  return (
    <>
      <div className="w-full overflow-hidden flex flex-col justify-center md:flex-row mt-24 text-3xl">
        <FooterContainer>
          <FooterTitle>About us</FooterTitle>
          <p className="text-xl text-gray-400">
            At DigiCode, your journey is rooted in a passion for redefining the
            digital landscape through innovate Web solutions.
          </p>
        </FooterContainer>
        <FooterContainer>
          <FooterTitle>Team member</FooterTitle>
          {FooterInfo[0].map(({ member }, index) => (
            <p className="text-xl text-gray-400" key={index}>
              {member}
            </p>
          ))}
        </FooterContainer>
        <FooterContainer>
          <FooterTitle>Contact Us</FooterTitle>
          {FooterInfo[1].map(({ info }, index) => (
            <p className="text-xl text-gray-400" key={index}>
              {info}
            </p>
          ))}
        </FooterContainer>
      </div>
      <hr className="border-t-2 border-white-600 mt-4 opacity-200" />
      <footer className="text-white flex items-center justify-center mt-6 text-2xl">
        <p>&copy; 2024 Copyright - Team DigiCode</p>
      </footer>
    </>
  );
};

export default index;
