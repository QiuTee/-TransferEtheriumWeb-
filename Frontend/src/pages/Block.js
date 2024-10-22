import React, { useEffect, useState } from "react";
import { DataGrid } from "@mui/x-data-grid";
import { ThemeProvider } from "@mui/material/styles";
import theme from "../components/Themes";
import { useBlockChain } from "../contexts/BlockchainContext";
import { ToastContainer } from "react-toastify";
import LoadingContainer from "../components/LoadingContainer";
import SearchBar from "../components/SearchBar";
import Blockslide from "../components/Blockslide/Blockslide";

const columns1 = [
  { field: "id", headerName: "ID", width: 60 },
  { field: "from", headerName: "From Address", width: 520 },
  { field: "to", headerName: "To Address", width: 520 },
  {
    field: "value",
    headerName: "Amount (ETH)",
    width: 180,
  },
];
const Block = () => {
  const { fetchBlock, fetchAllBlocks } = useBlockChain();
  const [allBlocks, setAllBlocks] = useState([]);
  const [block, setBlock] = useState([]);
  const [loading, setLoading] = useState(false);
  const [value, setValue] = useState("");
  const [filteredBlock, setFilteredBlock] = useState([]); // Make a shallow copy of the Block array
  const [clickedBlock, setClickedBlock] = useState("");
  const [allBlockLoading, setAllBlockLoading] = useState(false);
  useEffect(() => {
    async function fetchData() {
      setAllBlockLoading(true);
      try {
        const result = await fetchAllBlocks();
        setAllBlocks(result);
        setFilteredBlock(result);
      } catch (error) {
        console.error("Error fetching all blocks:", error);
      } finally {
        setAllBlockLoading(false);
      }
    }
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleChange = (event) => {
    const searchValue = event.target.value.toLowerCase();
    setValue(searchValue);
    if (searchValue === "") {
      // If search value is empty, display all blocks
      setFilteredBlock(allBlocks);
    } else {
      const filteredRows = allBlocks?.filter((row) =>
        Object.values(row).some((val) =>
          val.toString().toLowerCase().includes(searchValue)
        )
      );
      setFilteredBlock(filteredRows);
    }
  };
  const handleClick = (id) => {
    if (clickedBlock === id) {
      setClickedBlock("");
      return;
    }
    setClickedBlock(id);
  };
  // fetch data for transaction in block
  useEffect(() => {
    if (clickedBlock === "") return;

    async function fetchData() {
      setLoading(true);
      await fetchBlock(clickedBlock)
        .then((responseData) => {
          setBlock(responseData);
          setLoading(false); // Assuming you want to set loading to false after fetching data
        })
        .catch((error) => {
          // Handle errors if needed
          console.error("Error fetching block data:", error);
          setLoading(false); // Ensure loading is set to false even if there's an error
        });
    }
    fetchData(); // Call the async function immediately
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clickedBlock]);
  return (
    <>
      <div>
        <h1 className="sm:text-4xl text-3xl ml-4">Blocks on chain</h1>
        <p className="text-xl text-slate-500 ml-4">
          Click on block for more detail about transactions inside it
        </p>
      </div>
      <div className="flex flex-col w-full items-center justify-center my-8">
        <SearchBar value={value} handleChange={handleChange} />
        <div className="text-sm text-gray-400 mt-4">
          Found {filteredBlock?.length ? filteredBlock?.length : 0}{" "}
          {filteredBlock?.length >= 2 ? "results" : "result"}
        </div>
      </div>
      <div>
        {allBlockLoading ? (
          <LoadingContainer />
        ) : (
          <Blockslide
            handleClick={handleClick}
            data={filteredBlock}
            clickedBlock={clickedBlock}
          />
        )}
      </div>
      <div>
        {clickedBlock === "" ? null : (
          <>
            <div className="flex items-center justify-center pt-4">
              <div className="border border-white p-4 sm:w-[50%] w-[60% ] flex items-center justify-center h-[80px] rounded-xl">
                <div className="flex items-center flex-col sm:flex-row sm:ml-4 pb-5">
                  <h1 className="lg:text-3xl sm:text-xl pt-6">
                    Transaction inside block
                  </h1>
                  <p className="text-yellow-500 lg:text-3xl sm:text-xl ml-2 sm:pt-6 pt-2">
                    {clickedBlock.substring(0, 5) +
                      "..." +
                      clickedBlock.substring(clickedBlock.length - 5)}
                  </p>
                </div>
              </div>
            </div>
            <div className=" h-[400px] w-[90%] mx-auto mt-10">
              {loading ? (
                <LoadingContainer />
              ) : (
                <ThemeProvider theme={theme}>
                  <DataGrid
                    rows={block ? block : []}
                    columns={columns1}
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
    </>
  );
};

export default Block;
