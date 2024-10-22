import axios from "axios";
import { APIendpoint } from "../data";
const AxiosInstance = axios.create({
  baseURL: APIendpoint,
  timeout: 60000,
  headers: {
    "Content-Type": "application/json",
    accept: "application/json",
  },
});

export default AxiosInstance;
