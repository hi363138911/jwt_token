## Node.js+Mongoose的RestfulApi的用户token权限验证

# 非原创：抄袭 [文章地址](https://cnodejs.org/topic/58c1477b06dbd608756d0bca)，我感觉我修改的更容易理解，删除了passport模块，感觉没必要，修复了一些细节错误，另外作者本身对jwt理解有一些偏差。 不过还是一篇不错的入门文章。


具体数据库配置信息在config.js中设置,不开启数据库是会崩溃的。

### 整体构架
开发前先进行我们设计的构想

* 路由设计
    * POST /api/signup: 用户注册
    * POST /api/user/accesstoken: 账号验证,获取token
    * GET /api/users/info: 获得用户信息,需验证

* user 模型设计
    * name : 用户名
    * password: 密码
    * token: 验证相关token
    
### 关于RESTful API
网上已经有了很多关于RESTful的介绍，我这里也不过多重复了。想说的就是它的主要作用，就是对于现如今的网络应用程序，分为前端和后端两个部分，然而当前的发展趋势就是应用平台需求的扩大(IOS、Android、Webapp等等)

因此，就需要一种统一的机制，方便不同的应用平台的前端设备与后端进行通信，也就是前后端的分离。这导致了API架构的流行，甚至出现"API First"的设计思想。RESTful API则是目前比较成熟的一套互联网应用程序的API设计理论。
    
### 技术栈
使用Node.js上的[Express](http://www.expressjs.com.cn/)框架进行我们的路由设计，[Mongoose](https://cnodejs.org/topic/504b4924e2b84515770103dd)来与Mongodb数据库连接交互，使用Postman对我们设计的Api进行调试，快动起手来吧！


### API设计中的token的思路
在API设计中,TOKEN用来判断用户是否有权限访问API.TOKEN首先不需要编解码处理. 一般TOKEN都是一些用户名+时间等内容的MD5的不可逆加密.token是否匹配

具体实践过程主要为:

1. 设定一个密钥比如key = ‘2323dsfadfewrasa3434'。
2. 这个key 只有发送方和接收方知道。
3. 调用时，发送方，组合各个参数用密钥 key按照一定的规则(各种排序，MD5，ip等)生成一个accesskey。一起post提交到API接口。
4. 接收方拿到post过来的参数以及这个accesskey也和发送一样，用密钥key 对各个参数进行一样的规则(各种排序，MD5，ip等)也生成一个access_key2。
5. 对比 accesskey 和 accesskey2 。一样。则允许操作，不一样，报错返回或者加入黑名单。

### token设计具体实践

> 废话不多说，先进入看我们的干货，这次选用Node.js+experss配合Mongoose来进入REST的token实践



### 新建项目
先看看我们的项目文件夹

``` javascript
- routes/
---- index.js
---- users.js
- models/
---- user.js
- config.js
- package.json
- index.js
```

`npm init`创建我们的`package.json`

接着在项目根文件夹下安装我们所需的依赖

```
npm install express body-parser morgan mongoose jsonwebtoken bcrypt --save 

```
* express: 我们的主要开发框架
* mongoose: 用来与MongoDB数据库进行交互的框架，请提前安装好MongoDB在PC上
* morgan: 会将程序请求过程的信息显示在Terminal中，以便于我们调试代码
* jsonwebtoken: 用来生成我们的token
* bcrypt: 对用户密码进行hash加密

-- save会将我们安装的库文件写入`package.json`的依赖中,以便其他人打开项目是能够正确安装所需依赖.

### 用户模型
定义我们所需用户模型，用于moogoose，新建`models/user.js`

``` javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');

const UserSchema = new Schema({
  name: {
    type: String,
    unique: true, // 不可重复约束
    require: true // 不可为空约束
  },
  password: {
    type: String,
    require: true
  },
  token: {
    type: String
  }
});

// 添加用户保存时中间件对password进行bcrypt加密,这样保证用户密码只有用户本人知道
UserSchema.pre('save', function (next) {
    var user = this;
    if (this.isModified('password') || this.isNew) {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err) {
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    } else {
        return next();
    }
});
// 校验用户输入密码是否正确
UserSchema.methods.comparePassword = function(passw, cb) {
    bcrypt.compare(passw, this.password, (err, isMatch) => {
        if (err) {
            return cb(err);
        }
        cb(null, isMatch);
    });
};

module.exports = mongoose.model('User', UserSchema);

```

### 配置文件
`./config.js` 用来配置我们的MongoDB数据库连接和token的密钥。

```javascript
module.exports = {
  'secret': 'learnRestApiwithNickjs', // used when we create and verify JSON Web Tokens
  'database': 'mongodb://localhost:27017/test' // 填写本地自己 mongodb 连接地址,xxx为数据表名
};

```

### 本地服务器配置
`./index.js` 服务器配置文件，也是程序的入口。

这里我们主要用来包含我们程序需要加载的库文件，调用初始化程序所需要的依赖。

```javascript
const express = require('express');
const app = express();
const bodyParser = require('body-parser');// 解析body字段模块
const morgan = require('morgan'); // 命令行log显示
const mongoose = require('mongoose');
const routes = require('./routes');
const config = require('./config');

let port = process.env.PORT || 8080;

app.use(morgan('dev'));// 命令行中显示程序运行日志,便于bug调试
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json()); // 调用bodyParser模块以便程序正确解析body传入值

routes(app); // 路由引入

mongoose.Promise = global.Promise;
mongoose.connect(config.database); // 连接数据库

app.listen(port, () => {
  console.log('listening on port : ' + port);
})

```

### 路由配置
`./routes` 主要存放路由相关文件

`./routes/index.js` 路由总入口，引入所使用路由

```javascript
module.exports = (app) => {
  app.get('/', (req, res) => {
    res.json({ message: 'hello index!'});
  });

  app.use('/api', require('./users')); // 在所有users路由前加/api
};
```

`./routes/users.js`

``` javascript

const express = require('express');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const config = require('../config');
const passport = require('passport');
const router = express.Router();


// 注册账户
router.post('/signup', (req, res) => {
  if (!req.body.name || !req.body.password) {
    res.json({success: false, message: '请输入您的账号密码.'});
  } else {
    var newUser = new User({
      name: req.body.name,
      password: req.body.password
    });
    // 保存用户账号
    newUser.save((err) => {
      if (err) {
        return res.json({success: false, message: '注册失败!'});
      }
      res.json({success: true, message: '成功创建新用户!'});
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
      res.json({success: false, message:'认证失败,用户不存在!'});
    } else if(user) {
      // 检查密码是否正确
      user.comparePassword(req.body.password, (err, isMatch) => {
        if (isMatch && !err) {
          var token = jwt.sign({name: user.name}, config.secret,{
            expiresIn: 10080
          });
          user.token = token;
          user.save(function(err){
            if (err) {
              res.send(err);
            }
          });
          res.json({
            success: true,
            message: '验证成功!',
            token: 'Bearer ' + token,
            name: user.name
          });
        } else {
          res.send({success: false, message: '认证失败,密码错误!'});
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

```


主要验证发送的token值与用户服务器端token值是否匹配，进行信息验证。

### 具体调试

现在就可以运行我们的代码看具体运作过程了！为了便于调试与参数的收发，我们使用[postman](https://www.getpostman.com/)(可在Chrome上或Mac上安装)来操作.

`node index`运行我们的本地服务器，访问 [localhost:8080/]()
应该就可以看到我们所返回的初始json值了，然我们继续深入测试。

![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_2.png)

POST访问[localhost:8080/api/signup](),我们来注册一个新用户，注意要设置`body`的`Content-Type`为`x-www-form-urlencoded` 以便我们的`body-parser`能够正确解析,好的我们成功模拟创建了我们的新用户。

![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_4.png)

连接一下数据库看下我们的用户信息是否也被正确存储(注:我使用的是MongoChef,十分强大MongoDB数据库管理软件),我们可以看到,我的password也被正确加密保存了。

![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_5.png)

接着POST访问[localhost:8080/api/user/accesstoken](),来为我的用户获得专属token，POST过程与注册相关,可以看到也正确生成我们的token值。

![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_6.png)

再看下我们的数据库中的用户信息，token值也被存入了进来，便于我们之后进行权限验证。

![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_11.png)

GET访问[localhost:8080/api/users/info](),同时将我们的token值在`Header`中以 `Authorization: token` 传入,正确获得用户名则表示我们访问请求通过了验证。

![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_9.png)

如果token值不正确，则返回 Unauthorized 并拒绝访问请求。到这里我们的权限验证功能也就基本实现了(喜大普奔~)。
![](http://of30nsqpd.bkt.clouddn.com/Snip20161201_10.png)



