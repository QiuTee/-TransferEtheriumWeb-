import React, { useState } from "react";
import Signupbutton from "../components/Button/Signupbutton";
import { Profilefields } from "../data";
import checkEmail from "./../utils/checkEmail"; // Đã sử dụng
import checkPassword from "./../utils/checkPassword"; // Đã sử dụng
import { ToastContainer, toast } from "react-toastify";
import { useAuth } from "../contexts/AuthContext";
import submission from "./../utils/submission";
import LoadingContainer from "./../components/LoadingContainer";
import handleResponse from "../utils/handleResponse.js";

function Profile() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(false);

  const [form, setForm] = useState({
    email: user.email || "",
    phoneNumber: user.phoneNumber || "",
    first_name: user.firstName || "",
    last_name: user.lastName || "",
    password: "",
    confirmPassword: "",
    token: user.token,
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prevForm) => ({ ...prevForm, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);

    // Khởi tạo đối tượng requestData với các trường hợp định trước
    let requestData = {
      email: form.email !== user.email ? form.email : undefined,
      password: form.password ? form.password : undefined,
      confirmPassword: form.confirmPassword ? form.confirmPassword : undefined,
      token: form.token,
      profile: {
        last_name:
          form.last_name !== user.lastName ? form.last_name : undefined,
        first_name:
          form.first_name !== user.firstName ? form.first_name : undefined,
        phoneNumber:
          form.phoneNumber !== user.phoneNumber ? form.phoneNumber : undefined,
      },
    };

    // Loại bỏ các trường không cần thiết nếu không có thay đổi
    if (!requestData.email) delete requestData.email;
    if (!requestData.password) delete requestData.password;
    if (!requestData.confirmPassword) delete requestData.confirmPassword;
    if (!requestData.profile.last_name) delete requestData.profile.last_name;
    if (!requestData.profile.first_name) delete requestData.profile.first_name;
    if (!requestData.profile.phoneNumber)
      delete requestData.profile.phoneNumber;

    // Kiểm tra nếu requestData không có bất kỳ thay đổi nào
    if (
      !requestData.email &&
      !requestData.password &&
      !requestData.confirmPassword &&
      !requestData.profile.last_name &&
      !requestData.profile.first_name &&
      !requestData.profile.phoneNumber
    ) {
      toast.error("No changes detected.", { toastId: "toast" });
      setLoading(false);
      return;
    }

    // Kiểm tra email và mật khẩu nếu cần thiết
    const emailError = requestData.email ? checkEmail(requestData.email) : null;
    const [passwordError, retypePasswordError] = form.password
      ? checkPassword(form.password, form.confirmPassword)
      : [null, null];

    if (emailError) {
      toast.error(emailError, { toastId: "toast" });
    }
    if (passwordError || retypePasswordError) {
      toast.error(passwordError || retypePasswordError, { toastId: "toast" });
    }

    try {
      if (emailError || passwordError || retypePasswordError) {
        throw new Error("Please fix the errors in the form.");
      }

      const response = await submission("updateProfile", "put", requestData);
      if (response.status === "200 OK" && response.message) {
        toast.success(response.message, { toastId: "toast" });
      } else if (response.status === "401 Unauthorized" && response.message) {
        toast.error(response.message, { toastId: "toast" });
      }
    } catch (error) {
      toast.error(handleResponse(error.message), { toastId: "toast" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <form
        onSubmit={handleSubmit}
        className="flex flex-col items-center justify-center w-auto overflow-hidden"
      >
        {/* Profile Header */}
        <h1 className="text-3xl text-red-600">Profile settings</h1>

        {/* Profile Fields Section */}
        <div className="flex flex-col p-5">
          {/* Email and Phone Fields */}
          <div className="flex md:flex-row flex-col">
            {Profilefields[0].map((field) => (
              <div
                key={field.name}
                className={`flex ${
                  field.name !== "email" ? "md:ml-10 mt-4 md:mt-0" : ""
                }`}
              >
                <div className="flex flex-col text-2xl">
                  {field.label}:
                  <input
                    className="rounded-lg border-8 w-96 border-white text-black"
                    type={field.type}
                    name={field.name}
                    value={form[field.name]}
                    onChange={handleChange}
                  />
                </div>
              </div>
            ))}
          </div>
          {/* Last name and First Fields */}
          <div className="flex md:flex-row flex-col mt-4">
            {Profilefields[1].map((field) => (
              <div
                key={field.name}
                className={`flex ${
                  field.name !== "first_name" ? "md:ml-10 mt-4 md:mt-0" : ""
                }`}
              >
                <div className="flex flex-col text-2xl">
                  {field.label}:
                  <input
                    className="rounded-lg border-8 w-96 border-white text-black"
                    type={field.type}
                    name={field.name}
                    value={form[field.name]} // Ràng buộc giá trị với state
                    onChange={handleChange}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Password Fields */}
          <div className="flex md:flex-row flex-col mt-4">
            {Profilefields[2].map((field) => (
              <div
                key={field.name}
                className={`flex ${
                  field.name !== "password" ? "md:ml-10 mt-4 md:mt-0" : ""
                }`}
              >
                <div className="flex flex-col text-2xl">
                  {field.label}:
                  <input
                    className="rounded-lg border-8 w-96 border-white text-black"
                    type={field.type}
                    name={field.name}
                    value={form[field.name]}
                    onChange={handleChange}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Save Changes Button */}
        <div className="flex justify-center items-center pt-10">
          {loading ? (
            <LoadingContainer />
          ) : (
            <Signupbutton type="submit">Save Changes</Signupbutton>
          )}
        </div>
      </form>
      <ToastContainer
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover={false}
        theme="dark"
      />
    </>
  );
}

export default Profile;
