import { v2 } from 'cloudinary';

import app from "./app.js";
import connectToDb from "./config/db.js";


v2.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });

const port = process.env.PORT || 5009;

app.listen(port, async()=> {
    console.log(`listening on http://localhost:${port}`)
    await connectToDb();
})