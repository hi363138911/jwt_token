const express = require('express');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const config = require('../config');
const passport = require('passport');
const router = express.Router();

require('../passport')(passport);

// 注册账户
router.post('/signup', (req, res) => {
    if (!req.body.name || !req.body.password) {
        res.json({
            success: false,
            message: '请输入您的账号密码.'
        });
    } else {
        var newUser = new User({
            name: req.body.name,
            password: req.body.password
        });
        // 保存用户账号
        newUser.save((err) => {
            if (err) {
                return res.json({
                    success: false,
                    message: '注册失败!'
                });
            }
            res.json({
                success: true,
                message: '成功创建新用户!'
            });
        });
    }
});

// 检查用户名与密码并生成一个accesstoken如果验证通过
router.post('/user/accesstoken', (req, res) => {
    User.findOne({
        name: req.body.name
    }, (err, user) => {
        if (err) {
            throw err;
        }
        if (!user) {
            res.json({
                success: false,
                message: '认证失败,用户不存在!'
            });
        } else if (user) {
            // 检查密码是否正确
            user.comparePassword(req.body.password, (err, isMatch) => {
                if (isMatch && !err) {
                    //jwt生成token
                    var token = jwt.sign({
                        name: user.name
                    }, config.secret, {
                            expiresIn:  60 //秒到期时间
                        });
                    res.json({
                        success: true,
                        message: '验证成功!',
                        token: token,
                        name: user.name
                    });
                } else {
                    res.send({
                        success: false,
                        message: '认证失败,密码错误!'
                    });
                }
            });
        }
    });
});

// 根据token是否获取权限
router.get('/users/info', function (req, res) {5
    jwt.verify(req.query.token, config.secret, function (err, decoded) {
        if (err) {
            res.json({
                success: false,
                message: 'token error',
                err:err
            });
            
        } else {
            res.json({
                success: true,
                message: '通过权限',
                name: decoded.name
            });
        }

    });


});

module.exports = router;
