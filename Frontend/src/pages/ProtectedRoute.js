// Tran Thanh Minh - 103809048
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth(); // Get the authentication state
  const navigate = useNavigate();
  useEffect(() => {
    if (!isAuthenticated) {
      // If the user is not authenticated
      navigate("/login");
    }
  }, [isAuthenticated, navigate]);
  return isAuthenticated ? children : null;
}

export default ProtectedRoute;
