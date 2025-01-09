import { createContext, useEffect, useReducer } from "react";
import axios from "axios";

const initialState = {
  isAuthenticated: false,
  user: null,
};

const authReducer = (state, { type, payload }) => {
  switch (type) {
    case "LOGIN":
      return {
        ...state,
        isAuthenticated: true,
        user: payload.user,
      };
    case "LOGOUT":
      return {
        ...state,
        isAuthenticated: false,
        user: null,
      };
  }
};

const AuthContext = createContext({
  ...initialState,
  logIn: () => Promise.resolve(),
  register: () => Promise.resolve(),
  logOut: () => Promise.resolve(),
});

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  const getUserInfo = async () => {
    const token = localStorage.getItem("token");

    if (token) {
      try {
        const res = await axios.get(`/api/user/info`);
        axios.defaults.headers.common["x-auth-token"] = token;

        dispatch({
          type: "LOGIN",
          payload: {
            user: res.data.user,
          },
        });
      } catch (err) {
        console.error(err);
      }
    } else {
      delete axios.defaults.headers.common["x-auth-token"];
    }
  };

  // verify user on reducer state init or changes
  useEffect(async () => {
    if (!state.user) {
      await getUserInfo();
    }
  }, [state]);

  const logIn = async (email, password) => {
    const config = {
      headers: { "Content-Type": "application/json" },
    };
    const body = JSON.stringify({ email, password });

    try {
      const res = await axios.post(`/api/user/login`, body, config);
      localStorage.setItem("token", res.data.token);
      await getUserInfo();
    } catch (err) {
      console.error(err);
    }
  };

  const register = async (email, password) => {
    const config = {
      headers: { "Content-Type": "application/json" },
    };
    const body = JSON.stringify({ email, password });

    try {
      const res = await axios.post(`/api/user/register`, body, config);
      localStorage.setItem("token", res.data.token);
      await getUserInfo();
    } catch (err) {
      console.error(err);
    }
  };

  const logOut = async (name, email, password) => {
    try {
      localStorage.removeItem("token");
      dispatch({
        type: "LOGOUT",
      });
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <AuthContext.Provider value={{ ...state, logIn, register, logOut }}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
