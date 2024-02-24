import mongoose from 'mongoose';
import mongoosePaginate from 'mongoose-paginate-v2'

const userSchema = new mongoose.Schema({
    firstName: {type: String },
    lastName: {type: String }, 
    email: {
        type: String,
        unique: true,  
        sparse: true,
    },
    age: {type: Number },
    password: {type: String }, 
    role: {type: String, default: "user"},
    cart: { type: mongoose.Schema.Types.ObjectId,
            ref: 'Carts', 
        },
    provider: { type: String, default: "app" },
    githubId: { type: String, unique: true, sparse: true, default: undefined },
    resetLink: {
        token: { type: String, default: null },
        date: { type: Date, default: null },
    },
    documents: [
        {
            name: { type: String },
            reference: { type: String },
            uploadType: { type: String}
        }
    ],
    lastConnection:  { type: Date },
}, { timestamps: true });

userSchema.pre('findOne', function() {
    this.populate('cart.cartId');
});

userSchema.plugin(mongoosePaginate);
export default mongoose.model('User', userSchema);