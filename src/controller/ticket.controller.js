import ticketService from "../service/ticket.service.js";
import { nanoid } from "nanoid";
import cartsController from "./carts.controller.js";
import productsController from "./products.controller.js";
import { transporter } from "../app.js";
import config from "../config/envConfig.js";
import { createError } from '../utils/createError.js';
import errorList from '../utils/errorList.js';
export default class {
    static async createTicket(cid, userEmail) {
        try {

            const cartData = await cartsController.getCartContentById(cid);
            const purchasedProductsData = [];
            let amount = 0;
            
            for (const product of cartData.products) {
                const productId = product.productId._id;
            const quantity = product.quantity;
    
            const existingProduct = await productsController.getProductById(productId);
    
            if (existingProduct.status === true && existingProduct.stock >= quantity) {
                const updatedStock = existingProduct.stock - quantity;
    
                await productsController.updateProduct(productId, {
                    stock: updatedStock,
                });
                
                let productData = {
                    productId,
                    quantity,
                };
                
                amount += existingProduct.price * quantity;
                purchasedProductsData.push(productData);
                
                await cartsController.deleteProductOfCart(cid, productId);
            } else {
                if (existingProduct.status === false) {
                    console.log(`You cannot purchase the item ${productId} because it is not available.`);
                } else {
                    console.log(`There is not enough stock of the product ${productId}.`);
                }
            }
        }
        
        const uniqueCode = nanoid();
        const date = new Date();
        const ticket = await ticketService.createTicket(uniqueCode, date, amount, userEmail, purchasedProductsData);
        
        if(ticket){
            const mailOptions = {
                from: config.nodemailer.email,
                to: userEmail,
                subject: 'Your purchase ticket',
                text: `Hi from the apples shop!
                
                Thank you for purchasing on our online service. Here are the details of your most recent purchase:
                
                Ticket Code: ${ticket.code}
                Purchase Date: ${new Date(ticket.purchase_datetime).toLocaleString()}
                Amount: $${ticket.amount.toFixed(2)}
                Purchaser: ${ticket.purchaser}
                
                Products:
                ${ticket.products.map(product => `
                    Product ID: ${product.productId}
                    Quantity: ${product.quantity}
                    Product ID in Cart: ${product._id}
                `).join('\n')}
                
                See you next time!
                `
            };
            const info = await transporter.sendMail(mailOptions);

            console.log('Correo enviado: ' + info.response);
            return ticket;
        } else {
            return
        }
    }
    catch (error) {
        createError.Error({
            name: 'Creating ticket error',
            cause: error ,
            message: 'An error occured within the creating ticket method',
            code: errorList.INTERNAL_SERVER_ERROR,
        });
    }
}
}