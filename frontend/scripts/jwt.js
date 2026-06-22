function parseJwt(token) {
  const base64Url = token.split(".")[1];
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split("")
      .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
      .join(""),
  );
  return JSON.parse(jsonPayload);
}

function getUserInfo() {
  const token = localStorage.getItem("authToken");
  if (!token) return null;
  return parseJwt(token);
}

// Usage:
const user = getUserInfo();
if (user) {
  console.log("userId:", user.userId);
  console.log("username:", user.username);
}
