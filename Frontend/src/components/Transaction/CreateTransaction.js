import React, { useEffect, useState } from "react";
import Signupbutton from "../Button/Signupbutton";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import LoadingContainer from "../LoadingContainer";
import submission from "../../utils/submission";
import handleResponse from "../../utils/handleResponse";
import { useAuth } from "../../contexts/AuthContext";
const CreateTransaction = ({ fromAddress, setPendingInteraction, balance }) => {
  const { user, updateBalance } = useAuth();
  const [form, setForm] = useState({
    fromAddress: fromAddress,
    to_address: "",
    amount: "",
    pin: "", // Updated: Added pin field
    token: user.token,
  });
  const [loading, setLoading] = useState(false);

  const handleInputChange = (event) => {
    const { name, value } = event.target;
    setForm((prevForm) => ({ ...prevForm, [name]: value }));
  };

  useEffect(() => {
    setForm((prevForm) => ({ ...prevForm, fromAddress: fromAddress }));
  }, [fromAddress]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    if (form.amount > balance) {
      toast.error("You do not have enough balance to make this transaction", {
        toastId: "toast",
      });
      setLoading(false);
      return;
    }
    if (form.amount === "" || form.amount <= 0) {
      toast.error(
        form.amount === ""
          ? "Amount cannot be empty"
          : "Amount must be greater than 0",
        { toastId: "toast" }
      );
      setLoading(false);
      return;
    }

    // Check if any field is empty
    for (const key in form) {
      if (form[key] === "") {
        toast.error(
          `${key.charAt(0).toUpperCase() + key.slice(1)} field cannot be empty`,
          { toastId: "toast" }
        );
        setLoading(false);
        return;
      }
    }
    try {
      // convert form.amount from string to decimal
      form.amount = parseFloat(form.amount);
      const response = await submission("transaction", "post", form);
      if (response.status === "200 OK" && response.message) {
        updateBalance(response.data.balance);
        toast.success(
          `${
            response.message
              ? response.message
              : "Transaction created successfully"
          }`,
          { toastId: "toast" }
        );
        // wait for 2 second before redirecting
        setTimeout(() => {
          setPendingInteraction(true);
        }, 2000);
      } else {
        toast.error(
          `${
            response.message ? response.message : "Failed to create transaction"
          }`,
          { toastId: "toast" }
        );
      }
    } catch (error) {
      console.log(error);
      toast.error(handleResponse(error.message), { toastId: "toast" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="flex flex-col w-auto mx-auto items-center justify-center">
        <h2 className="flex justify-center pt-14 font-bold text-3xl md:text-4xl lg:text-5xl">
          Create Transaction
        </h2>

        <form onSubmit={handleSubmit}>
          {/* From Address Field */}
          <div className="flex flex-col text-2xl pt-10">
            {/* From Address Field */}
            <label
              htmlFor="fromAddress"
              className="text-2xl md:text-3xl lg:text-4xl"
            >
              From Address
            </label>
            <div className="pt-4">
              <input
                type="text"
                className="text-black rounded-lg border-8 sm:w-[500px] md:w-[900px] w-96 md:h-16 h-10 border-white text-xl md:text-2xl lg:text-3xl"
                id="fromAddress"
                value={form.fromAddress || 0}
                readOnly
              />
            </div>
            <p className="text-sm text-slate-400 md:w-full w-96 pt-2">
              This is your wallet address. You cannot change it because you can
              only spend your own coins.
            </p>
          </div>

          {/* To Address Field */}
          <div className="flex flex-col text-2xl pt-10">
            <label
              htmlFor="to_address"
              className="text-2xl md:text-3xl lg:text-4xl"
            >
              To Address
            </label>
            <div className="pt-4">
              <input
                type="text"
                className="text-black rounded-lg border-8 sm:w-[500px] md:w-[900px] w-96 md:h-16 h-10 border-white text-xl md:text-2xl lg:text-3xl"
                id="to_address"
                value={form.toAddress}
                name="to_address"
                onChange={handleInputChange}
              />
            </div>
            <p className="text-sm text-slate-400 md:w-full w-96 pt-2">
              The address of the wallet where you want to send the money to.
            </p>
            <p className="text-sm text-slate-400 md:w-full w-96 pt-2">
              Note: Please enter the correct address or you will lose all the
              transferred funds.
            </p>
          </div>

          {/* Amount Field */}
          <div className="flex flex-col text-2xl pt-10">
            <label
              htmlFor="amount"
              className="text-2xl md:text-3xl lg:text-4xl"
            >
              Amount (ETH)
            </label>
            <div className="pt-4">
              <input
                type="text"
                className="text-black rounded-lg border-8 sm:w-[500px] md:w-[900px] w-96 md:h-16 h-10 border-white text-xl md:text-2xl lg:text-3xl"
                id="amount"
                value={form.amount}
                name="amount"
                onChange={handleInputChange}
              />
            </div>
            <p className="text-sm text-slate-400 md:w-full w-96 pt-2">
              You can transfer any amount.
            </p>
          </div>

          {/* Private Key Field */}
          <div className="flex flex-col text-2xl pt-10">
            <label htmlFor="pin" className="text-2xl md:text-3xl lg:text-4xl">
              PIN
            </label>
            <div className="pt-4">
              <input
                type="text"
                className="text-black rounded-lg border-8 sm:w-[500px] md:w-[900px] w-96 md:h-16 h-10 border-white text-xl md:text-2xl lg:text-3xl"
                id="pin"
                value={form.pin}
                name="pin"
                onChange={handleInputChange} // Updated: Changed event handler
              />
            </div>
            <p className="text-sm text-slate-400 md:w-full w-96 pt-2">
              Please enter your pin key.
            </p>
          </div>

          {/* Submit Button */}
          <div className="flex justify-center pt-10">
            {loading ? (
              <LoadingContainer />
            ) : (
              <Signupbutton type="submit">
                Sign & Create Transaction
              </Signupbutton>
            )}
          </div>
        </form>
      </div>
      <ToastContainer
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover={false}
        theme="dark"
      />
    </>
  );
};

export default CreateTransaction;
