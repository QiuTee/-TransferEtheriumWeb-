// Tran Thanh Minh - 103809048
import { createContext, useContext, useReducer } from "react";
import { APIendpoint } from "../data";
import { toast } from "react-toastify";
import handleResponse from "../utils/handleResponse";
const AuthContext = createContext();
const initialState = {
  user: null,
  isAuthenticated: false,
};

function reducer(state, action) {
  switch (action.type) {
    case "login": // If the action type is login, then return the new state with the user and isAuthenticated
      return {
        ...state,
        user: action.payload,
        isAuthenticated: true,
      };
    case "logout": // If the action type is logout, then return the new state with the user and isAuthenticated
      return {
        ...state,
        user: null,
        isAuthenticated: false,
      };
    case "updateBalance":
      return {
        ...state,
        user: {
          ...state.user,
          balance: action.payload,
        },
      };
    default: // If the action type is not login or logout, then return the current state
      return state;
  }
}
function AuthProvider({ children }) {
  // The AuthProvider component will be used to wrap the App component
  const [{ user, isAuthenticated }, dispatch] = useReducer(
    reducer,
    initialState
  );
  // check if the API endpoint is not work, then the username and password will be compared with the FAKE_USER
  async function login({ username, password }) {
    // The login function will be used to login the user
    const formData = new FormData(); // Create a new FormData object
    formData.append("username", username); // Append the username and password to the FormData object
    formData.append("password", password);
    let result = undefined; // Initialize the result variable
    try {
      const response = await fetch(`${APIendpoint}/authenticate/login_api/`, {
        // Send a POST request to the login endpoint
        method: "POST",
        body: formData,
      });
      result = await response.json(); // Parse the response as JSON
      if (result.status === "200 OK" && result.data.token) {
        // If the response is successful
        dispatch({
          type: "login",
          payload: result.data,
        });
      } else if (result.status === "401 Unauthorized" && result.message) {
        // If the response is unauthorized
        toast.error(result.message, { toastId: "toast" });
      } else {
        // If the response is not successful
        toast.error(
          handleResponse(
            "We're currently facing connectivity issues. Please try again later."
          ),
          { toastId: "toast" }
        );
      }
    } catch (error) {
      console.log(error);
      toast.error(handleResponse(error.message), { toastId: "toast" });
    }

    return result;
  }

  const logout = () => {
    dispatch({
      type: "logout",
    });
  };
  const updateBalance = (value) => {
    dispatch({
      type: "updateBalance",
      payload: value,
    });
  };
  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        login,
        logout,
        updateBalance,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within a AuthProvider");
  }
  return context;
}
export { AuthProvider, useAuth };
