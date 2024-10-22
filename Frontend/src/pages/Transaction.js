import React, { useState } from "react";
import CreateTransaction from "../components/Transaction/CreateTransaction";
import Pending from "../components/Pending";
import SliderToggle from "../components/SliderToggle";
import { useAuth } from "../contexts/AuthContext";
const Transaction = () => {
  const { user } = useAuth();
  const [pending, setPending] = useState(false);
  const [selected, setSelected] = useState("light");
  const setPendingInteraction = (value) => {
    setPending(value);
    setSelected(value ? "dark" : "light");
  };
  return (
    <div className="overflow-hidden w-auto">
      <div className="flex flex-col md:flex-row m-4 w-full">
        <div className="basis-1/2 flex flex-col m-4 items-center justify-center">
          <h2 className="text-2xl sm:text-3xl md:text-4xl">
            Your Wallet Address:
          </h2>
          <p className="text-xl sm:text-2xl md:text-2xl">
            {user.address === null ? `Account Error` : user.address}
          </p>
        </div>
        <div className="basis-1/2 flex flex-col m-4 items-center justify-center">
          <h2 className="text-2xl sm:text-3xl md:text-4xl">Balance:</h2>
          {/* Displaying the balance in Ether */}
          <p className="text-xl sm:text-2xl md:text-2xl">
            {user.balance !== null ? `${user.balance} ETH` : "Loading..."}
          </p>
        </div>
      </div>

      <div
        className={`grid h-[50px] place-content-center px-4 transition-colors bg-black
      }`}
      >
        <SliderToggle
          selected={selected}
          setSelected={setSelected}
          setPending={setPending}
        />
      </div>
      <div className="flex justify-center">
        {pending ? (
          <Pending />
        ) : (
          <CreateTransaction
            fromAddress={user.address}
            setPendingInteraction={setPendingInteraction}
            balance={user.balance}
          />
        )}
      </div>
    </div>
  );
};

export default Transaction;
