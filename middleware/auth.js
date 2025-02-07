const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const token = req.header("x-auth-token");

  if (!token) {
    return res.status(401).json({ msg: "No Token, authorization denied." });
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
      if (error) {
        return res.status(401).json({ msg: "token is not valid." });
      } else {
        req.user = decoded.user;
        next();
      }
    });
  } catch (err) {
    console.error("something wrong with auth middleware.");
    res.status(500).json({ msg: "Server Error." });
  }
};
