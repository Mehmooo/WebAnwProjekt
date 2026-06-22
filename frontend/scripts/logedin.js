function checkAuth() {
  const token = localStorage.getItem("authToken");
  if (!token) {
    window.location.href = "/auth/login.html";
    return false;
  }
  if (!token || isTokenExpired(token)) {
    window.location.href = "/auth/login.html";
  }
  return true;
}

function isTokenExpired(token) {
  const payload = parseJwt(token);
  return payload.exp * 1000 < Date.now();
}

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
});
