import React, { useState, useEffect } from "react";
import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import "./Block.css";

const Blockslide = ({ data, handleClick, clickedBlock }) => {
  const [setting, setSetting] = useState({
    dots: true,
    infinite: false,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
  });

  useEffect(() => {
    function handleResize() {
      if (window.innerWidth > 1700) {
        setSetting((prevSetting) => ({
          ...prevSetting,
          slidesToShow: 5,
          slidesToScroll: 5,
        }));
      } else if (window.innerWidth > 1500 && window.innerWidth <= 1700) {
        setSetting((prevSetting) => ({
          ...prevSetting,
          slidesToShow: 4,
          slidesToScroll: 4,
        }));
      } else if (window.innerWidth > 1100 && window.innerWidth <= 1500) {
        setSetting((prevSetting) => ({
          ...prevSetting,
          slidesToShow: 3,
          slidesToScroll: 3,
        }));
      } else if (window.innerWidth > 700 && window.innerWidth <= 1100) {
        setSetting((prevSetting) => ({
          ...prevSetting,
          slidesToShow: 2,
          slidesToScroll: 2,
        }));
      } else {
        setSetting((prevSetting) => ({
          ...prevSetting,
          slidesToShow: 1.5,
          slidesToScroll: 1,
        }));
      }
    }
    window.addEventListener("resize", handleResize);
    handleResize();
    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <>
      <div className="overflow-hidden">
        <Slider key={JSON.stringify(data)} {...setting}>
          {data?.map(({ number, hash, previous_hash, nonce, timestamp }) => (
            <div
              className="hover-gradient flex justify-center items-center "
              key={number}
            >
              <div className="mt-[-2rem]">
                <div
                  className={`${
                    clickedBlock === hash ? "card " : ""
                  } mt-8 flex justify-center py-[0.3rem] border-slate-900 items-center text-white bg-slate-900 rounded-3xl w-[250px]`}
                  onClick={() => handleClick(hash)}
                >
                  <div className="flex flex-col items-center justify-center">
                    <h3 className="flex justify-center items-center z-20 border-b-2 border-white font-bold text-blue-400 text-xl">
                      Block {number}
                    </h3>
                    <div className="z-20">
                      <ul>
                        <li className="flex flex-col border-b-2 border-white py-2">
                          <p className="font-bold text-pink-500">Hash</p>
                          <p>
                            {hash.substring(0, 7) +
                              "..." +
                              hash.substring(hash.length - 7)}
                          </p>
                        </li>
                        <li className="flex flex-col border-b-2 border-white py-2">
                          <p className="font-bold text-pink-500">
                            Hash of Previous Block
                          </p>
                          <p>
                            {previous_hash.substring(0, 7) +
                              "..." +
                              previous_hash.substring(previous_hash.length - 7)}
                          </p>
                        </li>
                        <li className="flex flex-col border-b-2 border-white py-2">
                          <p className="font-bold text-pink-500">Nonce</p>
                          <p>{nonce}</p>
                        </li>
                        <li className="flex flex-col py-2">
                          <p className="font-bold text-pink-500">Time stamp</p>
                          <p>{timestamp}</p>
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </Slider>
      </div>
    </>
  );
};

export default Blockslide;
