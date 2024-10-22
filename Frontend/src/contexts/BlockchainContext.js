import { createContext, useContext, useReducer } from "react";
import { toast } from "react-toastify";
import handleResponse from "./../utils/handleResponse";
import submission from "../utils/submission";
import { useAuth } from "./AuthContext";
const BlockchainContext = createContext();
const initialState = {
  data: { history: [], pending: [], block: [], all_blocks: [] },
  isValid: false,
};
function reducer(state, action) {
  switch (action.type) {
    case "history":
      return {
        ...state,
        data: {
          ...state.data,
          history: action.payload,
        },
      };
    case "pending":
      return {
        ...state,
        data: {
          ...state.data,
          pending: action.payload,
        },
      };
    case "block":
      return {
        ...state,
        data: {
          ...state.data,
          block: action.payload,
        },
      };
    case "all_blocks":
      return {
        ...state,
        data: {
          ...state.data,
          all_blocks: action.payload,
        },
      };
    case "reset":
      return initialState;
    default:
      return state;
  }
}
function BlockchainProvider({ children }) {
  const [{ data, isValid }, dispatch] = useReducer(reducer, initialState);
  const { user } = useAuth();
  async function History() {
    try {
      const response = await submission("history", "post", {
        token: user.token,
      });
      const result = await response;
      if (result.status === "200 OK") {
        dispatch({ type: "history", payload: result.data });
        toast.success("History fetched successfully", { toastId: "toast" });
        return result.data;
      }
    } catch (error) {
      toast.error(handleResponse(error.message, "History"), {
        toastId: "toast",
      });
      console.log(error);
    }
  }
  async function Pending() {
    try {
      const response = await submission("pending", "post", {
        token: user.token,
      });
      const result = await response;
      if (result.status === "200 OK") {
        toast.success("Pending transactions fetched successfully", {
          toastId: "toast",
        });
        dispatch({ type: "pending", payload: result.data });
        return result.data;
      } else {
        toast.error("Pending transactions failed", { toastId: "toast" });
      }
    } catch (error) {
      toast.error(handleResponse(error.message, "Pending"), {
        toastId: "toast",
      });
      console.log(error);
    }
  }
  async function fetchAllBlocks() {
    try {
      const response = await submission("block", "get");
      const result = await response;
      if (result.status === "200 OK") {
        dispatch({ type: "all_blocks", payload: result.data });
        return result.data;
      } else {
        toast.error("Fetch all blocks failed", { toastId: "toast" });
      }
    } catch (error) {
      console.log(error);
      toast.error(handleResponse("Fetch all blocks failed"), {
        toastId: "toast",
      });
    }
  }
  async function fetchBlock(block_id) {
    try {
      const response = await submission("block/" + block_id, "get");
      const result = await response;
      if (result.status === "200 OK") {
        dispatch({ type: "block", payload: result });
        return result.data;
      } else {
        toast.error("Fetch block failed", { toastId: "toast" });
      }
    } catch (error) {
      console.log(error);
      toast.error(handleResponse("Fetch block failed"), { toastId: "toast" });
    }
  }
  const reset = () => {
    dispatch({ type: "reset" });
  };
  return (
    <BlockchainContext.Provider
      value={{
        data,
        isValid,
        History,
        Pending,
        fetchBlock,
        reset,
        fetchAllBlocks,
      }}
    >
      {children}
    </BlockchainContext.Provider>
  );
}

function useBlockChain() {
  const context = useContext(BlockchainContext);
  if (!context) {
    throw new Error("useBlockChain must be used within a BlockchainProvider");
  }
  return context;
}
export { BlockchainProvider, useBlockChain };
