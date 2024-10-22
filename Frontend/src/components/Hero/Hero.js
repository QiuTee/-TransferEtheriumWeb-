//Nguyen Do Nhat Nam-104061616
import React from "react";
import "./Hero.css";
import Homebutton from "../Button/Homebutton";

// Functional component for rendering Hero section
const Hero = () => {
  return (
    <section className="hero-container">
      {/* Hero Content */}
      <div className="hero-content">
        <h2>
          {/* Strong tag for emphasizing */}
          <strong>Decentral Xchange System</strong>
        </h2>
        <p>
          A revolutionary decentralized trading platform leveraging blockchain
          technology and smart contracts for a secure, transparent, and
          efficient user experience.
        </p>
        {/* Home Button */}
        <Homebutton>Get Started</Homebutton>
      </div>

      {/* Hero Image */}
      <div className="hero-img">
        <div className="w-full">
          <div className="sign-icon tech-icon w-1/5 mb-8">
            {/* Locker Image */}
            <img
              className="sign-icon"
              src="./images/homemain/locker-dynamic-premium.png"
              alt="locker"
            />
          </div>
          {/* Security Image */}
          <img
            className=""
            src="./images/homemain/Security-amico.png"
            alt="Security"
          />
        </div>

        {/* Additional Tech Icons */}
        <div>
          <div className="tech-icon w-1/5 mr-20">
            {/* Card Image */}
            <img src="./images/homemain/card-dynamic-premium.png" alt="card" />
          </div>
          <div className="tech-icon w-1/5 mr-20">
            {/* Shield Image */}
            <img
              src="./images/homemain/sheild-dynamic-premium.png"
              alt="shield"
            />
          </div>
          <div className="tech-icon w-1/5">
            {/* Dollar Image */}
            <img
              src="./images/homemain/dollar-dynamic-premium.png"
              alt="dollar"
            />
          </div>
        </div>
      </div>
    </section>
  );
};

export default Hero;
