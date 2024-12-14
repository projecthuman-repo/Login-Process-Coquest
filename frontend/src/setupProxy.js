// Setup proxy
const { createProxyMiddleware } = require("http-proxy-middleware");
const { Config } = require("./config");

module.exports = function (app) {
  app.use(
    "/api",
    createProxyMiddleware({
      target: Config.API_URL,
      changeOrigin: true,
    })
  );
};
