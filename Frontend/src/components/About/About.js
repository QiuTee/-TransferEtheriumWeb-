//Nguyen Do Nhat Nam-104061616
import React from "react";
import { teammember } from "../../data";
import "./About.css";

const About = () => {
  return (
    <div className="flex flex-col w-full">
      <div className="flex justify-center items-center font-bold text-5xl">
        <h1>About Us</h1>
      </div>
      <div className="flex md:flex-row flex-col">
        {/* Mapping through the first set of people data */}
        {teammember.map(
          ({ image, github, linkedin, name, description, role }) => (
            // Using a fragment to avoid unnecessary divs
            <div className="shadow-2xl m-2" key={name}>
              <div className="team-item">
                <div className="flex items-center justify-center">
                  <img src={image} className="team-img" alt="pic" />
                </div>
                <h3>{name}</h3>
                <div className="team-info">
                  <p>{role}</p>
                </div>
                <p className="text-black">{description}</p>
                <ul className="team-icon">
                  <li>
                    <a
                      href={github}
                      className="github"
                      target="_blank"
                      rel="noreferrer"
                    >
                      <i className="fa-brands fa-github"></i>
                    </a>
                  </li>
                  <li>
                    <a
                      href={linkedin}
                      className="linkedin"
                      target="_blank"
                      rel="noreferrer"
                    >
                      <i className="fa-brands fa-linkedin"></i>
                    </a>
                  </li>
                </ul>
              </div>
            </div>
          )
        )}
      </div>
    </div>
  );
};

export default About;
