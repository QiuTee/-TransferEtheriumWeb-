// Tran Thanh Minh - 103809048
import * as React from "react";
import Box from "@mui/material/Box";
import TextField from "@mui/material/TextField";
import SearchIcon from "@mui/icons-material/Search";
import { ThemeProvider } from "@mui/material/styles";
import theme from "../Themes";
export default function SearchBar({ value, handleChange }) {
  return (
    <ThemeProvider theme={theme}>
      <Box sx={{ display: "flex", alignItems: "flex-end" }}>
        <SearchIcon sx={{ color: "action.active", mr: 1, my: 0.5 }} />
        <TextField
          id="input-with-sx"
          label="Search"
          variant="standard"
          value={value} // Pass the value as a prop
          onChange={handleChange} // Pass the handleChange function as a prop
        />
      </Box>
    </ThemeProvider>
  );
}
