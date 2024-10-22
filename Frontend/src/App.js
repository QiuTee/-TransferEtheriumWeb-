// Tran Thanh Minh - 103809048
import React from "react";
import { AuthProvider } from "./contexts/AuthContext";
import { BlockchainProvider } from "./contexts/BlockchainContext";
import PageNotFound from "./pages/PageNotFound";
import ProtectedRoute from "./pages/ProtectedRoute";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import Signup from "./pages/Signup";
import Login from "./pages/Login";
import Profile from "./pages/Profile";
import Footer from "./components/Footer";
import Navbar from "./components/Navbar";
import History from "./pages/History";
import Transaction from "./pages/Transaction";
import Verify from "./pages/Verify";
import Block from "./pages/Block";
import Forgotpassword from "./pages/Forgotpassword";
import Changepassword from "./pages/Changepassword";
function App() {
  return (
    <>
      <AuthProvider>
        <BlockchainProvider>
          {/* Wrap the entire app with the AuthProvider */}
          <BrowserRouter>
            {" "}
            {/* Wrap the entire app with the BrowserRouter */}
            <Navbar /> {/* Render the Navbar component */}
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/login" element={<Login />} />
              <Route
                path="settings"
                element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                }
              />
              <Route
                path="history"
                element={
                  <ProtectedRoute>
                    <History />
                  </ProtectedRoute>
                }
              />
              <Route
                path="transaction"
                element={
                  <ProtectedRoute>
                    <Transaction />
                  </ProtectedRoute>
                }
              />
              <Route path="/signup" element={<Signup />} />{" "}
              <Route path="/block" element={<Block />} />
              <Route path="/verify" element={<Verify />} />
              <Route path="/forgotpw" element={<Forgotpassword />} />
              <Route path="/changepw" element={<Changepassword />} />
              <Route path="*" element={<PageNotFound />} />
            </Routes>
          </BrowserRouter>
        </BlockchainProvider>
      </AuthProvider>
      <Footer /> {/* Render the Footer component */}
    </>
  );
}

export default App;
