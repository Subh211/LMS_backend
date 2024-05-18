import mongoose from "mongoose";
mongoose.set('strictQuery', false);

const connectToDb = async () => {
    try {
        const connection = await mongoose.connect(process.env.MONGODB_URL);
        if (connection) {
            console.log(`Connected to mongoose :${connection}`)
        }
    } catch (error) {
        console.log(error.message)
        process.exit(1)
    }
}

export default connectToDb;