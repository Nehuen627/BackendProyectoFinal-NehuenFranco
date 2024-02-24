import { Router } from 'express';
import passport from 'passport';
import usersController from '../controller/users.controller.js';
import { tokenGenerator} from '../utils/utils.js';
import { v4 as uuidv4 } from 'uuid';
import config from '../config/envConfig.js'
import { transporter } from "../app.js";

const router = Router();

router.post('/sessions/register', passport.authenticate('register', { failureRedirect: '/register' }), async (req, res) => {
    res.redirect('/login');
});

router.post('/sessions/login', passport.authenticate('login', { failureRedirect: '/login' }), async (req, res) => {

    const token = tokenGenerator(req.user)
    if(req.user.role === "admin"){
        res
        .cookie('access_token', token, { maxAge: 1000*60*30, httpOnly: true, signed: true })
        .status(200)
        .redirect('/api/products');
    } else {
        const date = Date()
        const connection = await usersController.lastConnection(req.user._id, date)
        if(connection){
            res
            .cookie('access_token', token, { maxAge: 1000*60*30, httpOnly: true, signed: true })
            .status(200)
            .redirect('/api/products');
        } else {
            res.redirect('/login')
        }
    }
});
router.get('/sessions/current', passport.authenticate('current', { failureRedirect: '/login' }), async (req, res) => {
    const currentUser = req.user;
    res.json({ user: currentUser });
});

router.post('/sessions/login-github', async (req, res) => {
    try {
        const { body:{ email } } = req;
        let user = req.user
        if (user.email === undefined) {
            const newUser = await usersController.updateData("email", email, req.user._id);
            const token = tokenGenerator(newUser)
            res
            .cookie('access_token', token, { maxAge: 1000*60*30, httpOnly: true, signed: true })
            .status(200)
            .redirect('/api/products');
        }
    } catch (error) {
        res.redirect('/login');
    }
});


router.get('/sessions/github', passport.authenticate('github', { scope: ['user:email'] }));

router.get('/sessions/github-callback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
    const user = req.user;

    if (!user.email) {
        const token = tokenGenerator(user)
        res
        .cookie('access_token', token, { maxAge: 1000*60*30, httpOnly: true, signed: true })
        .status(200)
        .redirect('/login-github');
    } else {
        const token = tokenGenerator(req.user)
        res
        .cookie('access_token', token, { maxAge: 1000*60*30, httpOnly: true, signed: true })
        .status(200)
        .redirect('/api/products'); 
    }
})
router.get('/sessions/logout', passport.authenticate('currentProfile', { session: false }), async (req, res) => {
    if(req.user.role === "admin"){
        res
        .clearCookie('access_token')
        .redirect('/login')
    } else {
        const date = Date()
        const connection = await usersController.lastConnection(req.user._id, date)
        if(connection){
            res
            .clearCookie('access_token')
            .redirect('/login')
        } else {
            res.redirect('/profile')
        }
    }

});
router.post('/sessions/changePassword', async (req, res) => {
    try {
        const { body:{ email } } = req;
        const user = await usersController.findEmail(email);
        if (user){
            const finalToken = uuidv4()
            await usersController.generateLink(email, finalToken);
            const url = config.url
            const mailOptions = {
                from: config.nodemailer.email,
                to: email,
                subject: 'Reset your password',
                text: `Hi from the apples shop!
                
                Are you wanting to change your password?
                Click on this link below and follow the instructions:
                ${url}/resetPassword/${user._id}/${finalToken}
                If you did not request a new password please ignore this message.
                `
            };
            const mail = await transporter.sendMail(mailOptions); 
            if(mail){            
                res.render('waiting')
            } else {
                console.error(`Error sending reset password email to ${user.email}`);
            } 
        } else {
            res.redirect('/changePassword');
        }
    }
    catch (error) {
        req.logger.error(error)
        res.redirect('/changePassword');
    }
})
router.post('/sessions/trueChangePassword', async (req, res) => {
    try {
        const { body:{ uid, password } } = req;
        const exist = await usersController.findById(uid);
        if (exist){
            const updated = await usersController.updateData("password", password, exist._id);
            if(updated){
                res.redirect('/login')
            } else {
                res.status(401).send("You can not use the same password")
            }
        } else {
            res.redirect('/changePassword');
        }
    }
    catch (error) {
        res.redirect('/changePassword');
    }
})

export default router;
