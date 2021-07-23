const dbConfig = {
  user: process.env.DB_USER || "sa",
  password: process.env.DB_PASS || "mis",
  server: process.env.DB_SERVER || "localhost",
  options: {
    enableArithAbort: true,
    encrypt: false,
    trustServiceCertificate: true,
    database: process.env.DB_NAME || "OrderingDB",
  },
};

module.exports = dbConfig;
