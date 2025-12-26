const path = require('path');
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

const app = express();
const db = new Database(path.join(__dirname, '../data/ecommerce.db'));

// 初始化数据库表
function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('customer','admin')),
      email TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      stock INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      total_amount REAL NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      price REAL NOT NULL,
      FOREIGN KEY(order_id) REFERENCES orders(id),
      FOREIGN KEY(product_id) REFERENCES products(id)
    );
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action_type TEXT NOT NULL,
      detail TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);
}

initDb();

// 视图与静态资源
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// 中间件
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: 'ecommerce-secret',
    resave: false,
    saveUninitialized: false
  })
);

// 简单邮件发送配置（实验用，可按需改为真实 SMTP）
const transporter = nodemailer.createTransport({
  // 实验环境使用 jsonTransport，实际部署时可改为 QQ 邮箱 SMTP 等
  jsonTransport: true
});

// 统一渲染提示页
function renderMessage(res, status, message, backUrl) {
  res.status(status || 200).render('message', {
    title: '提示',
    message,
    backUrl: backUrl || 'javascript:history.back()'
  });
}

// 辅助函数
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  next();
}

function logAction(userId, type, detail) {
  const stmt = db.prepare(
    "INSERT INTO logs (user_id, action_type, detail, created_at) VALUES (?,?,?,datetime('now','localtime'))"
  );
  stmt.run(userId || null, type, detail || '');
}

// 首页 & 产品展示
app.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products').all();
  res.render('index', { user: req.session.user, products });
});

// 注册
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  try {
    const stmt = db.prepare(
      'INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)'
    );
    stmt.run(username, password, 'customer', email || null);
    res.redirect('/login');
  } catch (e) {
    res.render('register', { error: '用户名已存在或数据错误' });
  }
});

// 登录/注销
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db
    .prepare('SELECT * FROM users WHERE username = ? AND password = ?')
    .get(username, password);
  if (!user) {
    return res.render('login', { error: '用户名或密码错误' });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  logAction(user.id, 'login', '用户登录');
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  if (req.session.user) {
    logAction(req.session.user.id, 'logout', '用户注销');
  }
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// 购物车（保存在 session）
app.post('/cart/add/:id', requireLogin, (req, res) => {
  const productId = parseInt(req.params.id, 10);
  if (!req.session.cart) req.session.cart = {};
  const product = db
    .prepare('SELECT stock FROM products WHERE id = ?')
    .get(productId);
  if (!product) {
    return renderMessage(res, 404, '商品不存在', '/');
  }
  const currentQty = req.session.cart[productId] || 0;
  if (currentQty + 1 > product.stock) {
    // 不允许超过库存加入购物车
    return renderMessage(
      res,
      400,
      '加入购物车数量超过库存，请调整数量或联系管理员补货。',
      '/cart'
    );
  }
  req.session.cart[productId] = currentQty + 1;
  logAction(req.session.user.id, 'add_to_cart', `添加商品 ${productId}`);
  res.redirect('/');
});

app.get('/cart', requireLogin, (req, res) => {
  const cart = req.session.cart || {};
  const productIds = Object.keys(cart);
  let items = [];
  let total = 0;
  if (productIds.length) {
    const stmt = db.prepare(
      `SELECT * FROM products WHERE id IN (${productIds.map(() => '?').join(',')})`
    );
    items = stmt.all(...productIds).map((p) => {
      const quantity = cart[p.id];
      const amount = quantity * p.price;
      total += amount;
      return { product: p, quantity, amount };
    });
  }
  res.render('cart', { user: req.session.user, items, total });
});

// 购物车删除单个商品
app.post('/cart/remove/:id', requireLogin, (req, res) => {
  const productId = parseInt(req.params.id, 10);
  if (req.session.cart && req.session.cart[productId]) {
    delete req.session.cart[productId];
    logAction(req.session.user.id, 'remove_from_cart', `移除商品 ${productId}`);
  }
  res.redirect('/cart');
});

// 下单 + 支付（简化）
app.post('/checkout', requireLogin, (req, res) => {
  const cart = req.session.cart || {};
  const productIds = Object.keys(cart);
  if (!productIds.length) return res.redirect('/cart');

  let total = 0;
  const products = db
    .prepare(
      `SELECT * FROM products WHERE id IN (${productIds.map(() => '?').join(',')})`
    )
    .all(...productIds);
  // 检查库存是否足够
  for (const p of products) {
    const quantity = cart[p.id];
    if (quantity > p.stock) {
      return renderMessage(
        res,
        400,
        '下单数量超过库存，请返回购物车调整后再试。',
        '/cart'
      );
    }
    total += p.price * quantity;
  }

  // 创建订单
  const insertOrder = db.prepare(
    "INSERT INTO orders (user_id, status, total_amount, created_at) VALUES (?,?,?,datetime('now','localtime'))"
  );
  const orderResult = insertOrder.run(
    req.session.user.id,
    'PAID',
    total.toFixed(2)
  );
  const orderId = orderResult.lastInsertRowid;

  const insertItem = db.prepare(
    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)'
  );
  products.forEach((p) => {
    const quantity = cart[p.id];
    insertItem.run(orderId, p.id, quantity, p.price);
    // 下单后减少库存
    db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?').run(
      quantity,
      p.id
    );
  });

  // 清空购物车
  req.session.cart = {};
  logAction(req.session.user.id, 'checkout', `下单订单 ${orderId}`);

  // 发送“确认收货”邮件（实验用：控制台输出 JSON）
  const user = db
    .prepare('SELECT * FROM users WHERE id = ?')
    .get(req.session.user.id);
  if (user && user.email) {
    transporter.sendMail(
      {
        // 按要求使用管理员邮箱作为发件人
        from: '2769136843@qq.com',
        to: user.email,
        subject: `订单确认 - #${orderId}`,
        text: `您的订单 #${orderId} 已付款，总金额：${total.toFixed(
          2
        )}，请登录网站查看订单详情。`
      },
      () => {}
    );
  }

  res.redirect('/orders');
});

// 顾客订单列表
app.get('/orders', requireLogin, (req, res) => {
  const orders = db
    .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.session.user.id);
  res.render('orders', { user: req.session.user, orders });
});

// 管理后台：商品管理
app.get('/admin/products', requireAdmin, (req, res) => {
  const products = db.prepare('SELECT * FROM products').all();
  res.render('admin_products', { user: req.session.user, products });
});

app.post('/admin/products/create', requireAdmin, (req, res) => {
  const { name, description, price, stock } = req.body;
  // 价格与库存校验：价格>=0，最多两位小数；库存为非负整数
  const priceNum = parseFloat(price);
  const stockNum = parseInt(stock, 10);
  const priceValid =
    !Number.isNaN(priceNum) && priceNum >= 0 && /^\d+(\.\d{1,2})?$/.test(price);
  const stockValid =
    !Number.isNaN(stockNum) && Number.isInteger(stockNum) && stockNum >= 0;
  if (!priceValid || !stockValid) {
    return renderMessage(
      res,
      400,
      '价格或库存不合法：价格需为非负且最多两位小数，库存需为非负整数',
      '/admin/products'
    );
  }
  db.prepare(
    'INSERT INTO products (name, description, price, stock) VALUES (?,?,?,?)'
  ).run(name, description, priceNum, stockNum);
  logAction(req.session.user.id, 'product_create', `新增商品 ${name}`);
  res.redirect('/admin/products');
});

app.post('/admin/products/:id/update', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, description, price, stock } = req.body;
  const priceNum = parseFloat(price);
  const stockNum = parseInt(stock, 10);
  const priceValid =
    !Number.isNaN(priceNum) && priceNum >= 0 && /^\d+(\.\d{1,2})?$/.test(price);
  const stockValid =
    !Number.isNaN(stockNum) && Number.isInteger(stockNum) && stockNum >= 0;
  if (!priceValid || !stockValid) {
    return renderMessage(
      res,
      400,
      '价格或库存不合法：价格需为非负且最多两位小数，库存需为非负整数',
      '/admin/products'
    );
  }
  db.prepare(
    'UPDATE products SET name=?, description=?, price=?, stock=? WHERE id=?'
  ).run(name, description, priceNum, stockNum, id);
  logAction(req.session.user.id, 'product_update', `修改商品 ${id}`);
  res.redirect('/admin/products');
});

app.post('/admin/products/:id/delete', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.prepare('DELETE FROM products WHERE id=?').run(id);
  logAction(req.session.user.id, 'product_delete', `删除商品 ${id}`);
  res.redirect('/admin/products');
});

// 管理后台：订单管理 + 销售统计
app.get('/admin/orders', requireAdmin, (req, res) => {
  const orders = db
    .prepare(
      `SELECT o.*, u.username 
       FROM orders o 
       JOIN users u ON o.user_id = u.id 
       ORDER BY o.created_at DESC`
    )
    .all();
  const stats = db
    .prepare(
      'SELECT COUNT(*) AS orderCount, SUM(total_amount) AS totalSales FROM orders'
    )
    .get();
  res.render('admin_orders', { user: req.session.user, orders, stats });
});

// 管理后台：客户管理 + 日志
app.get('/admin/customers', requireAdmin, (req, res) => {
  const customers = db
    .prepare("SELECT id, username, email FROM users WHERE role = 'customer'")
    .all();
  res.render('admin_customers', { user: req.session.user, customers });
});

app.get('/admin/logs', requireAdmin, (req, res) => {
  const logs = db
    .prepare(
      `SELECT l.*, u.username 
       FROM logs l 
       LEFT JOIN users u ON l.user_id = u.id 
       ORDER BY l.created_at DESC 
       LIMIT 200`
    )
    .all();
  res.render('admin_logs', { user: req.session.user, logs });
});

// 初始化一个管理员账号（默认：admin/123456）
function ensureAdmin() {
  const admin = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get('admin');
  if (!admin) {
    db.prepare(
      'INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)'
    ).run('admin', '123456', 'admin', 'admin@example.com');
  }
}

ensureAdmin();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`E-commerce site listening on http://localhost:${PORT}`);
});


