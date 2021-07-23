require("dotenv").config({ path: "./process.env" });

// const Connection = require("tedious").Connection;
// const Request = require("tedious").Request;
// const { ConnectionError } = require("tedious");
const express = require("express");
const dbConfig = require("./db-config");
const sql = require("mssql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());

app.listen(port, (err) => {
  if (err) {
    console.log(err);
  } else {
    console.log(`Server runnning on port ${port}`);
  }
});

const verifyToken = (req, res, next) => {
  const header = req.headers["authorization"];
  if (typeof header === typeof undefined) {
    res.send(400);
  } else {
    const token = header.split(" ")[1];
    jwt.verify(token, "verySecretKey", function (err, decoded) {
      if (err) {
        res.json({ message: err });
      } else {
        next();
      }
    });
  }
};

//create table for users if not exists
sql.connect(dbConfig, function (err) {
  if (err) {
    console.log(err);
  } else {
    sql
      .query(
        `use ${process.env.DB_NAME} 
        if not exists (select top 1 * from sys.objects where name = 'users' and schema_id = 1 and type_desc = 'USER_TABLE') 
        begin 
        create table dbo.users 
          (user_id int identity(1, 1) primary key
          , last_name varchar(50)
          , first_name varchar(50)
          , middle_name varchar(50)
          , email varchar(50)
          , password varchar(200)
          , is_active int
          , date_added datetime default getdate()
          , date_modified datetime default getdate()) 
        end`
      )
      .then((result) => {
        console.log(result);
      })
      .catch((err) => {
        console.log(err);
      });
  }
});

//create
app.post("/api/register", (req, res) => {
  const lname = req.body.last_name;
  const fname = req.body.first_name;
  const mname = req.body.middle_name;
  const email = req.body.email;
  const password = req.body.password;
  const saltRounds = 10;
  sql.connect(dbConfig, function (err) {
    if (err) {
      console.log(err);
    } else {
      bcrypt.hash(password, saltRounds, function (err, hashedPassword) {
        const request = new sql.Request();
        request.stream = true;
        request.input("lname", lname);
        request.input("fname", fname);
        request.input("mname", mname);
        request.input("email", email);
        request.input("password", hashedPassword);
        request
          .query(
            `use ${process.env.DB_NAME} 
            insert into dbo.users 
            (last_name, first_name, middle_name, email, password, is_active) 
            values (@lname, @fname, @mname, @email, @password, 1)`
          )
          .then((result) => {
            res.json({
              message: "User successfully added!",
            });
          })
          .catch((err) => {
            console.log(err);
          });
      });
    }
  });
});

//read
app.post("/api/sign-in/", (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  sql.connect(dbConfig, function (err) {
    if (err) {
      console.log(err);
    } else {
      const request = new sql.Request();
      request.input("email", email);
      request
        .query(
          `use ${process.env.DB_NAME} 
          select * 
          from dbo.users 
          where email = @email`
        )
        .then((row) => {
          bcrypt.compare(
            password,
            row.recordset[0].password,
            function (err, result) {
              if (result) {
                const token = jwt.sign(
                  {
                    user_id: row.recordset[0].user_id,
                    email: row.recordset[0].email,
                  },
                  "verySecretKey",
                  { expiresIn: "30s" }
                );
                res.json({ message: "Login successful!", token: token });
              } else {
                res.json({ message: "Invalid email or password!" });
              }
            }
          );
        })
        .catch((err) => {
          res.json({ message: "Invalid email or password!" });
        });
    }
  });
});

//read
app.get("/api/users", verifyToken, (req, res, next) => {
  sql.connect(dbConfig, function (err) {
    if (err) {
      console.log(err);
    } else {
      const request = new sql.Request();
      request.query(
        `use ${process.env.DB_NAME} 
        select * 
        from dbo.users`,
        (err, result) => {
          res.json(result.recordset);
        }
      );
    }
  });
});

//read - searching
app.get("/api/users/:id", (req, res, next) => {
  const id = req.params.id;
  sql.connect(dbConfig, function (err) {
    if (err) {
      console.log(err);
    } else {
      const request = new sql.Request();
      request.input("user_id", id);
      request
        .query(
          `use ${process.env.DB_NAME} 
          select * 
          from dbo.users 
          where user_id = @user_id`
        )
        .then((result) => {
          res.json(result.recordset);
        });
    }
  });
});

//delete
app.delete("/api/users/", (req, res, next) => {
  const id = req.body.id;
  sql.connect(dbConfig, function (err) {
    if (err) {
      console.log(err);
    } else {
      const request = new sql.Request();
      request.input("user_id", id);
      request
        .query(
          `use ${process.env.DB_NAME} 
          delete 
          from dbo.users 
          where user_id = @user_id`
        )
        .then((result) => {
          if (typeof result.recordset == undefined) {
            res.json(`User deleted successfully!`);
          } else {
            res.json(`User does not exists!`);
          }
        })
        .catch((err) => {
          console.log(err);
        });
    }
  });
});

//update
app.put("/api/users/edit/:id", (req, res, next) => {
  const lname = req.body.last_name;
  const fname = req.body.first_name;
  const mname = req.body.middle_name;
  const email = req.body.email;
  const password = req.body.password;
  const isActive = req.body.isActive;
  const userid = req.params.id;
  sql.connect(dbConfig, function (err) {
    if (err) {
      console.log(err);
    } else {
      bcrypt.hash(password, 10, function (err, hashedPassword) {
        if (err) {
          console.log(err);
        } else {
          const request = new sql.Request();
          request.stream = true;
          request.input("userid", userid);
          request.input("lname", lname);
          request.input("fname", fname);
          request.input("mname", mname);
          request.input("email", email);
          request.input("password", hashedPassword);
          request.input("active", isActive);
          request
            .query(
              `use ${process.env.DB_NAME} 
                update dbo.users 
                set last_name = @lname
                , first_name = @fname
                , middle_name = @mname
                , email = @email
                , password = @password
                , is_active = @active
                , date_modified = getdate()
                where user_id = @userid`
            )
            .then((result) => {
              res.json({ message: "Record updated successfully!" });
            })
            .catch((err) => {
              console.log(err);
            });
        }
      });
    }
  });
});

// const connection = new Connection(dbConfig);

// connection.on("connect", (err) => {
//   if (err) {
//     console.log(err);
//   } else {
//     console.log(`Connected`);
//   }
// });

// connection.connect();
// sql.connect(dbConfig, function (err) {
//   if (err) {
//     console.log(err);
//   } else {
//     console.log(``);
//   }
// });
