// Tran Thanh Minh - 103809048
import { createTheme } from "@mui/material";
// Theme for MUI components
const theme = createTheme({
  palette: {
    mode: "dark",
  },
  components: {
    MuiBox: {
      root: {
        width: "100%",
      },
    },
    MuiFormControl: {
      styleOverrides: {
        root: {
          width: "300px",
        },
      },
    },
    MuiDataGrid: {
      styleOverrides: {
        root: {
          overflowX: "auto",
        },
        columnHeaderTitleContainer: {
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        },
        cell: {
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: "100px",
        },
        footer: {
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        },
      },
    },
  },
});

export default theme;
