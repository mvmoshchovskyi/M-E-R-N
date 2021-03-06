const {Router} = require('express')
const User = require('../models/User')
const config = require('config')
const router = Router()
const {check, validationResult} = require('express-validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post(
    '/register',
    [
        check('email', ' not correct email').isEmail(),
        check('password', ' min length of password must be grather than 6')
            .isLength({min: 6})
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: ' not correct data of registration'
                })
            }
            const {email, password} = req.body
            const candidate = await User.findOne({email})
            if (candidate) {
                return res.status(400).json({message: ' this user is exists'})
            }
            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({email, password: hashedPassword})
            await user.save()
            res.status(201).json({message: 'user was created'})
        } catch (e) {
            res.status(500).json({message: ' something went wrong'})
        }
    })
router.post(
    '/login',
    [
        check('email', ' enter correct emaill').normalizeEmail().isEmail(),
        check('password', ' enter password').exists()
            .isLength({min: 6})
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: ' not correct data of enter in system'
                })
            }
            const {email, password} = req.body
            const user = await User.findOne({email})
            if (!user) {
                return res.status(400).json({message: ' user not found'})
            }
            const isMatch = await bcrypt.compare(password, user.password)
            if (isMatch) {
                return res.status(400).json({message: 'not correct password'})
            }
            const token = jwt.sign(
                {userId: user.id},
                config.get('jwtSecret'),
                {expiresIn: '1d'}
            )
            res.json({token, userId: user.id})
        } catch (e) {
            res.status(500).json({message: ' something went wrong'})
        }
    })
module.exports = router
