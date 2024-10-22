import { motion } from "framer-motion";
import { GrTransaction } from "react-icons/gr";
import { MdPendingActions } from "react-icons/md";
const TOGGLE_CLASSES =
  "text-sm font-medium flex items-center gap-2 px-3 md:pl-3 md:pr-3.5 py-3 md:py-1.5 transition-colors relative z-10";

const SliderToggle = ({ selected, setSelected, setPending }) => {
  return (
    <div className="relative flex w-fit items-center rounded-full">
      <button
        className={`${TOGGLE_CLASSES} ${
          selected === "light" ? "text-white" : "text-slate-300"
        }`}
        onClick={() => {
          setSelected("light");
          setPending(false);
        }}
        style={{ fontSize: "1.5rem" }}
      >
        <GrTransaction className="relative z-10 text-lg md:text-sm" />
        <span className="relative z-10 mr-5">Transaction</span>
      </button>
      <button
        className={`${TOGGLE_CLASSES} ${
          selected === "dark" ? "text-white" : "text-slate-300"
        }`}
        onClick={() => {
          setSelected("dark");
          setPending(true);
        }}
        style={{ fontSize: "1.5rem" }}
      >
        <MdPendingActions className="relative z-10 text-lg md:text-sm" />
        <span className="relative z-10 mr-5">Pending</span>
      </button>
      <div
        className={`absolute inset-0 z-0 flex ${
          selected === "dark" ? "justify-end" : "justify-start"
        }`}
      >
        <motion.span
          layout
          transition={{ type: "spring", damping: 15, stiffness: 250 }}
          className="h-full w-1/2 rounded-full bg-gradient-to-r from-violet-600 to-indigo-600"
        />
      </div>
    </div>
  );
};

export default SliderToggle;
