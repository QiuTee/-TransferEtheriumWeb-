// Tran Thanh Minh - 103809048
import { Link } from "react-router-dom";
// Page not found component
export default function PageNotFound() {
  return (
    <div className="flex h-screen items-center justify-center text-center">
      <h1>Page not found 😢</h1>
      <br />
      <Link to="/">Back to Home</Link>
    </div>
  );
}
