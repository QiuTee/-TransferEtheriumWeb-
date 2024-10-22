// Tran Thanh Minh - 103809048
import React from "react";
import CircularProgress from "@mui/material/CircularProgress";

const LoadingContainer = () => {
  return (
    <div className="flex w-full overflow-hidden items-center justify-center">
      {/* Loading indicator */}
      <CircularProgress color="secondary" />
    </div>
  );
};

export default LoadingContainer;
