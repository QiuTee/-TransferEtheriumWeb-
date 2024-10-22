// Nguyen Do Nhat Nam-104061616 - Tran Thanh Minh - 103809048
import React, { useEffect, useState } from "react";
import { DataGrid } from "@mui/x-data-grid";
import { ThemeProvider } from "@mui/material/styles";
import theme from "../components/Themes";
import SearchBar from "../components/SearchBar";
import { useBlockChain } from "../contexts/BlockchainContext";
import { ToastContainer } from "react-toastify";
import LoadingContainer from "../components/LoadingContainer";
const columns = [
  { field: "id", headerName: "ID", width: 60 },
  { field: "from", headerName: "From Address", width: 520 },
  { field: "to", headerName: "To Address", width: 520 },
  {
    field: "amount",
    headerName: "Amount (ETH)",
    width: 180,
  },
  {
    field: "timestamp",
    headerName: "Time Stamp",
    width: 280,
  },
  {
    field: "valid",
    headerName: "Valid",
    width: 70,
    valueGetter: (params) => (params.value ? "✔" : "✘"),
  },
];

export default function History() {
  const [value, setValue] = useState("");
  const { History, data } = useBlockChain();
  const [loading, setLoading] = useState(false);
  // eslint-disable-next-line no-unused-vars
  const [originalHistory, setOriginalHistory] = useState(data.pending);
  const [filteredHistory, setFilteredHistory] = useState(data.pending);
  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      const result = await History().then((result) => {
        setLoading(false);
        return result; // Return result from the then block
      });
      setOriginalHistory(result);
      setFilteredHistory(result);
    }
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleChange = (event) => {
    const searchValue = event.target.value; // Use event.target.value directly
    setValue(searchValue);

    const filteredRows = originalHistory.filter((row) =>
      Object.values(row).some((val) =>
        val.toString().toLowerCase().includes(searchValue.toLowerCase())
      )
    );

    setFilteredHistory(filteredRows);
  };

  return (
    <div className="flex flex-col">
      <h1 className="text-center text-4xl font-bold my-4">
        Transaction History
      </h1>
      <div className="flex flex-col w-full items-center justify-center my-8">
        <SearchBar value={value} handleChange={handleChange} />
        <div className="text-sm text-gray-400 mt-4">
          Found {filteredHistory?.length}{" "}
          {filteredHistory?.length === 1 ? "result" : "results"}
        </div>
      </div>
      <div className="h-auto w-[90%] mx-auto mb-36">
        {loading ? (
          <LoadingContainer />
        ) : (
          <ThemeProvider theme={theme}>
            <DataGrid
              rows={filteredHistory}
              columns={columns}
              initialState={{
                pagination: {
                  paginationModel: { page: 0, pageSize: 5 },
                },
              }}
              pageSizeOptions={[5, 10]}
              style={{
                fontSize: "20px",
              }}
              className="overflow-auto"
              autoHeight
              getRowId={(row) => row.id}
            />
          </ThemeProvider>
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
