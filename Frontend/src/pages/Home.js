//Nguyen Do Nhat Nam-104061616
import React from "react";
import Hero from "../components/Hero/Hero";
import Bordermain from "../components/Border/Bordermain";
import Information from "../components/Information/Information";
import Customer from "../components/Autoscrolling/Customer";
import About from "../components/About/About";
const App = () => {
  return (
    <>
      {/* Hero Section */}
      <div className="max-w-screen-2xl mx-auto relative lg:px-6">
        <Hero />
      </div>

      {/* Border Main Section */}
      <div className="flex flex-col items-center justify-center mt-24 w-auto overflow-hidden">
        <Bordermain />
      </div>

      {/* Information Section */}
      <div>
        <Information />
      </div>
      {/* {About Section} */}
      <div className="flex flex-row">
        <About />
      </div>

      {/* Customer Section */}
      <div>
        <Customer />
      </div>
    </>
  );
};

export default App;
