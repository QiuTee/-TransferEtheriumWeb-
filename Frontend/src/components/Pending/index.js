import React, { useEffect, useState } from "react";
import { DataGrid } from "@mui/x-data-grid";
import { ThemeProvider } from "@mui/material/styles";
import theme from "../Themes";
import { useBlockChain } from "../../contexts/BlockchainContext";
import { ToastContainer, toast } from "react-toastify";
import Pendingbutton from "../Button/Pendingbutton";
import LoadingContainer from "../LoadingContainer";
import handleResponse from "../../utils/handleResponse";
import submission from "../../utils/submission";
import { useAuth } from "../../contexts/AuthContext";
import Signupbutton from "../Button/Signupbutton";
const columns = [
  { field: "id", headerName: "ID", width: 60 },
  { field: "transaction_hash", headerName: "Transaction Hash", width: 520 },
  { field: "receiver", headerName: "Receiver", width: 520 },
  { field: "amount", headerName: "Amount (ETH)", width: 180 },
  { field: "timestamp", headerName: "Time Stamp", width: 280 },
];

export default function Pending() {
  const { user, updateBalance } = useAuth();
  const { Pending, data } = useBlockChain();
  const [pending, setPending] = useState(data.pending);
  const [loading, setLoading] = useState(false);
  const [buttonloading, setButtonLoading] = useState(false);
  const [formData, setFormData] = useState({
    token: user.token,
    pin: "",
    item: "",
  });

  const handlepinChange = (event) => {
    const { value } = event.target;
    if (/^\d*$/.test(value)) {
      setFormData((prevFormData) => ({
        ...prevFormData,
        pin: value,
      }));
    }
  };
  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      try {
        const result = await Pending();
        setPending(result);
      } catch (error) {
        console.error("Error fetching pending data:", error);
        toast.error(handleResponse(error.message), { toastId: "toast" });
      } finally {
        setLoading(false);
      }
    }
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const handleSubmit = async (action) => {
    setButtonLoading(true);
    if (formData.item === "") {
      toast.error("Please select a transaction", { toastId: "toast" });
      setButtonLoading(false);
      return;
    }
    if (formData.item?.length === 0) {
      toast.error("Please select a transaction", {
        toastId: "toast",
      });
      setButtonLoading(false);
      return;
    }
    if (formData.pin === "") {
      toast.error("Please enter your PIN", { toastId: "toast" });
      setButtonLoading(false);
      return;
    }
    try {
      const updateFormData = {
        ...formData,
        action: action,
      };
      const response = await submission("execute", "post", updateFormData);
      const result = await response;
      if (result.status === "200 OK") {
        updateBalance(result.data.balance);
        setPending(result.data.history);
        toast.success(
          `${result.message ? result.message : "Sending Ether Successfully"}`,
          { toastId: "toast" }
        );
      } else {
        toast.error(
          `${result.message ? result.message : "Error with sending Ether"}`,
          { toastId: "toast" }
        );
      }
    } catch (error) {
      console.log(error);
      toast.error(handleResponse(error.message), { toastId: "toast" });
    } finally {
      setButtonLoading(false);
    }
  };
  return (
    <div className="flex flex-col">
      <h2 className="flex justify-center pt-14 font-bold text-3xl md:text-4xl lg:text-5xl mb-8">
        Pending Transaction
      </h2>
      <div className="h-auto xl:w-[75%] lg:w-[60%] md:w-[45%] w-[20%] mx-auto">
        {loading ? (
          <LoadingContainer />
        ) : (
          <ThemeProvider theme={theme}>
            <DataGrid
              rows={pending}
              columns={columns}
              initialState={{
                pagination: { paginationModel: { page: 0, pageSize: 5 } },
              }}
              pageSizeOptions={[5, 10]}
              style={{ fontSize: "20px" }}
              className="overflow-auto"
              autoHeight
              getRowId={(row) => row.id}
              onRowSelectionModelChange={(rows) => {
                setFormData((prevFormData) => ({
                  ...prevFormData,
                  item:
                    rows.length > 0
                      ? pending[rows[0] - 1].contract_address || ""
                      : "",
                }));
              }}
            />
          </ThemeProvider>
        )}
      </div>
      <div className="flex justify-center items-center flex-col pt-6">
        <p className="text-4xl pb-2">PIN</p>
        <input
          type="text"
          className="text-black rounded-lg border-8 xl:w-[70%] sm:w-[30%] md:w-[40%] lg:w-[50%] border-white text-xl md:text-2xl lg:text-3xl"
          placeholder="Enter your PIN"
          value={formData.pin}
          onChange={handlepinChange}
        />
        <p className="text-slate-400 text-sm pt-2">Please enter your PIN</p>
      </div>
      <div className="flex items-center justify-center mt-6">
        {buttonloading ? (
          <LoadingContainer />
        ) : (
          <>
            <div className="mx-4">
              <Signupbutton
                type="button"
                onClick={() => handleSubmit("execute")}
              >
                Confirm Sending
              </Signupbutton>
            </div>
            <div className="mx-4">
              <Pendingbutton
                type="button"
                onClick={() => handleSubmit("withdraw")}
              >
                Withdraw
              </Pendingbutton>
            </div>
          </>
        )}
      </div>

      <ToastContainer
        position="top-right"
        autoClose={2000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover={false}
        theme="dark"
      />
    </div>
  );
}
