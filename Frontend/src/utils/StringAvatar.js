import StringToColor from "./StringToColor.js";
export default function StringAvatar(name) {
  return {
    sx: {
      bgcolor: StringToColor(name),
    },
    children: `${name.split(" ")[0][0]}${name.split(" ")[1][0]}`,
  };
}
