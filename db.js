const mongoose = require('mongoose');

require('dotenv').config();



const connectToMongo =  async ()=>{
        
    if(mongoose.connections[0].readyState){
        console.log("Mongodb already connected")
    }
    await mongoose.connect(process.env.MONGO_URI)
    console.log("Mongodb Connected")

}


module.exports =  connectToMongo;
