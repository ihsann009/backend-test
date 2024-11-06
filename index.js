import express from "express";
import db from "./config/database.js"
import router from "./routes/index.js";
import cookieParser from "cookie-parser";
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(cookieParser());

try {
    await db.authenticate();
    console.log('Database terkonek');
    
} catch (error) {
    console.log(error);
}

// db.sync()
//   .then(() => {
//     console.log('Database & tables created!');
//   })
//   .catch((error) => {
//     console.error('Error creating database:', error);
//   });

app.use(express.json());
app.use(router);

app.listen(5000,() => {
    console.log('The server running on port 5000')
})