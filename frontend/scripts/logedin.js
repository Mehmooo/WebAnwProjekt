function checkAuth() {
  const token = localStorage.getItem("authToken");
  if (!token) {
    window.location.href = "/auth/login.html";
    return false;
  }
  return true;
}

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
});
