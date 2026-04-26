const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 3000;
const SERVER_IP = '8.130.185.30';
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('[SECURITY] 警告：未设置环境变量 JWT_SECRET，正在使用固定默认密钥。生产环境请务必设置强密钥！');
}
const SECRET = JWT_SECRET || 'buffalo_default_jwt_secret_2024_v7';

// ============ 安全中间件 ============
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"]
    }
  },
  hsts: false,
  crossOriginEmbedderPolicy: false
}));

app.use(hpp());

// CORS 白名单
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  `http://${SERVER_IP}:3000`,
  `http://${SERVER_IP}`
];
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('CORS策略阻止了该来源的请求'));
  },
  credentials: true
}));

// 请求限制
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 全局API速率限制
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10000,
  message: { error: '请求过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// 登录接口更严格的速率限制
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '登录尝试次数过多，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/auth/login', loginLimiter);

// ============ 数据库 ============
const dbPath = path.join(__dirname, 'buffalo.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    dept TEXT NOT NULL,
    role TEXT NOT NULL,
    password TEXT NOT NULL DEFAULT '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    customer TEXT NOT NULL,
    model TEXT NOT NULL,
    qty INTEGER DEFAULT 1,
    delivery TEXT,
    status TEXT DEFAULT 'pending',
    processes TEXT,
    qc TEXT,
    created TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bom (
    id TEXT PRIMARY KEY,
    code TEXT,
    model TEXT,
    name TEXT NOT NULL,
    qty INTEGER DEFAULT 0,
    material TEXT,
    unitWeight REAL,
    totalWeight REAL,
    unit TEXT,
    manufacturer TEXT,
    remark TEXT,
    status TEXT DEFAULT 'enough',
    changes TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS inventory (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    spec TEXT,
    category TEXT,
    material TEXT,
    qty INTEGER DEFAULT 0,
    min INTEGER DEFAULT 10,
    max INTEGER DEFAULT 0,
    unit TEXT,
    price REAL,
    location TEXT,
    remark TEXT,
    status TEXT DEFAULT 'enough',
    changes TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS inv_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id TEXT,
    type TEXT,
    item_name TEXT,
    qty INTEGER,
    remark TEXT,
    time INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT,
    action TEXT,
    target TEXT,
    detail TEXT,
    ip TEXT,
    time INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    module TEXT,
    description TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER,
    permission_id INTEGER,
    PRIMARY KEY (role_id, permission_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER,
    role_id INTEGER,
    PRIMARY KEY (user_id, role_id)
  )`);
});

// ============ 初始化演示数据 ============
function initDemoData() {
  const users = [
    {id:1, name:'张总', dept:'管理部', role:'总经理'},
    {id:2, name:'李经理', dept:'管理部', role:'经理'},
    {id:3, name:'王工', dept:'技术部', role:'工程师'},
    {id:4, name:'刘工', dept:'技术部', role:'工程师'},
    {id:5, name:'陈工', dept:'生产部', role:'主管'},
    {id:6, name:'杨工', dept:'生产部', role:'工人'},
    {id:7, name:'赵工', dept:'质检部', role:'质检员'},
    {id:8, name:'周工', dept:'质检部', role:'质检员'},
    {id:9, name:'吴工', dept:'销售部', role:'销售员'},
    {id:10, name:'郑工', dept:'采购部', role:'采购员'},
    {id:11, name:'孙工', dept:'仓库', role:'仓管'},
    {id:12, name:'钱工', dept:'技术部', role:'工程师'}
  ];

  const defaultPassword = bcrypt.hashSync('123456', 10);

  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (err || row.count > 0) return;
    const stmt = db.prepare("INSERT INTO users (id, name, dept, role, password) VALUES (?, ?, ?, ?, ?)");
    users.forEach(u => stmt.run(u.id, u.name, u.dept, u.role, defaultPassword));
    stmt.finalize();
  });

  db.get("SELECT COUNT(*) as count FROM orders", (err, row) => {
    if (err || row.count > 0) return;
    const today = new Date();
    const orders = [
      {id:'BF0426N546A', customer:'玖龙纸业', model:'BL61-S4900', qty:2, delivery:new Date(today.getTime()+30*86400000).toISOString().split('T')[0], status:'production', processes:JSON.stringify([true,true,true,true,true,false,false,false]), qc:JSON.stringify([true,true,false,false,false,false]), created:new Date().toISOString()},
      {id:'BF0426N545A', customer:'山东金锣', model:'BL60-S3200', qty:1, delivery:new Date(today.getTime()+25*86400000).toISOString().split('T')[0], status:'production', processes:JSON.stringify([true,true,true,false,false,false,false,false]), qc:JSON.stringify([true,false,false,false,false,false]), created:new Date().toISOString()},
      {id:'BF0326N539A', customer:'宁波亚洲', model:'BL61-S3300', qty:2, delivery:new Date(today.getTime()-12*86400000).toISOString().split('T')[0], status:'overdue', processes:JSON.stringify([true,true,true,true,true,true,false,false]), qc:JSON.stringify([true,true,true,false,false,false]), created:new Date().toISOString()},
      {id:'BF0326N538A', customer:'武汉裕大', model:'BL50-S2100', qty:1, delivery:new Date(today.getTime()+45*86400000).toISOString().split('T')[0], status:'pending', processes:JSON.stringify([false,false,false,false,false,false,false,false]), qc:JSON.stringify([false,false,false,false,false,false]), created:new Date().toISOString()},
      {id:'BF0326N537A', customer:'苏州恒力', model:'BL61-S4500', qty:3, delivery:new Date(today.getTime()+60*86400000).toISOString().split('T')[0], status:'qc', processes:JSON.stringify([true,true,true,true,true,true,true,true]), qc:JSON.stringify([true,true,true,true,true,false]), created:new Date().toISOString()},
      {id:'BF0226N536A', customer:'南通恒科', model:'BL61-S4900', qty:2, delivery:new Date(today.getTime()-38*86400000).toISOString().split('T')[0], status:'overdue', processes:JSON.stringify([true,true,true,true,true,true,false,false]), qc:JSON.stringify([true,true,true,false,false,false]), created:new Date().toISOString()},
      {id:'BF0226N535A', customer:'江西晨鸣', model:'BL60-S2800', qty:1, delivery:new Date(today.getTime()+90*86400000).toISOString().split('T')[0], status:'completed', processes:JSON.stringify([true,true,true,true,true,true,true,true]), qc:JSON.stringify([true,true,true,true,true,true]), created:new Date().toISOString()},
      {id:'BF0126N532A', customer:'天津锦祥', model:'BL50-S1800', qty:2, delivery:new Date(today.getTime()+120*86400000).toISOString().split('T')[0], status:'completed', processes:JSON.stringify([true,true,true,true,true,true,true,true]), qc:JSON.stringify([true,true,true,true,true,true]), created:new Date().toISOString()},
      {id:'BF1225N530A', customer:'江苏博汇', model:'BL61-S5200', qty:1, delivery:new Date(today.getTime()+15*86400000).toISOString().split('T')[0], status:'production', processes:JSON.stringify([true,true,true,true,false,false,false,false]), qc:JSON.stringify([true,false,false,false,false,false]), created:new Date().toISOString()},
      {id:'BF1225N529A', customer:'重庆理文', model:'BL60-S3500', qty:2, delivery:new Date(today.getTime()+35*86400000).toISOString().split('T')[0], status:'pending', processes:JSON.stringify([false,false,false,false,false,false,false,false]), qc:JSON.stringify([false,false,false,false,false,false]), created:new Date().toISOString()},
      {id:'BF1125N525A', customer:'河北华泰', model:'BL61-S4800', qty:1, delivery:new Date(today.getTime()+50*86400000).toISOString().split('T')[0], status:'pending', processes:JSON.stringify([false,false,false,false,false,false,false,false]), qc:JSON.stringify([false,false,false,false,false,false]), created:new Date().toISOString()},
      {id:'BF1125N524A', customer:'福建联盛', model:'BL50-S2000', qty:3, delivery:new Date(today.getTime()+75*86400000).toISOString().split('T')[0], status:'pending', processes:JSON.stringify([false,false,false,false,false,false,false,false]), qc:JSON.stringify([false,false,false,false,false,false]), created:new Date().toISOString()}
    ];
    const stmt = db.prepare("INSERT INTO orders (id, customer, model, qty, delivery, status, processes, qc, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    orders.forEach(o => stmt.run(o.id, o.customer, o.model, o.qty, o.delivery, o.status, o.processes, o.qc, o.created));
    stmt.finalize();
  });

  db.get("SELECT COUNT(*) as count FROM bom", (err, row) => {
    if (err || row.count > 0) return;
    const boms = [
      {id:'BOM001', code:'FAN-001', model:'BH53M21226', name:'叶片', qty:1, material:'铝合金', unitWeight:25.5, totalWeight:25.5, unit:'片', manufacturer:'自产', remark:'标准叶片', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'BOM002', code:'FAN-002', model:'BH53M21226', name:'轮毂', qty:1, material:'铸铁', unitWeight:18.2, totalWeight:18.2, unit:'个', manufacturer:'自产', remark:'', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'BOM003', code:'FAN-003', model:'BH53M21226', name:'轴承', qty:2, material:'轴承钢', unitWeight:2.5, totalWeight:5, unit:'套', manufacturer:'SKF', remark:'22218', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'BOM004', code:'FAN-004', model:'BH53M21226', name:'电机', qty:1, material:'', unitWeight:150, totalWeight:150, unit:'台', manufacturer:'西门子', remark:'11kW', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'BOM005', code:'FAN-005', model:'BH53M21226', name:'机壳', qty:1, material:'Q235', unitWeight:80, totalWeight:80, unit:'个', manufacturer:'自产', remark:'', status:'enough', changes:JSON.stringify(['','','',''])}
    ];
    const stmt = db.prepare("INSERT INTO bom (id, code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    boms.forEach(b => stmt.run(b.id, b.code, b.model, b.name, b.qty, b.material, b.unitWeight, b.totalWeight, b.unit, b.manufacturer, b.remark, b.status, b.changes));
    stmt.finalize();
  });

  db.get("SELECT COUNT(*) as count FROM inventory", (err, row) => {
    if (err || row.count > 0) return;
    const invs = [
      {id:'INV001', name:'钢板 Q235 6mm', spec:'6mm×1500×6000', category:'板材', material:'Q235', qty:120, min:50, max:200, unit:'张', price:580, location:'A区-01-01', remark:'', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'INV002', name:'角钢 L50×5', spec:'50×50×5mm', category:'型材', material:'Q235', qty:85, min:30, max:150, unit:'根', price:45, location:'A区-01-02', remark:'', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'INV003', name:'轴承 SKF 22218', spec:'22218CC/W33', category:'标准件', material:'轴承钢', qty:8, min:10, max:30, unit:'套', price:680, location:'B区-02-01', remark:'SKF原装进口', status:'low', changes:JSON.stringify(['','','',''])},
      {id:'INV004', name:'电机 Y160M-4', spec:'11kW/4P', category:'电机', material:'', qty:18, min:5, max:20, unit:'台', price:2800, location:'C区-01-01', remark:'含安装附件', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'INV005', name:'三角带 B2500', spec:'B2500', category:'传动件', material:'橡胶', qty:150, min:50, max:200, unit:'条', price:28, location:'B区-03-01', remark:'', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'INV006', name:'螺栓 M16×60', spec:'M16×60 8.8级', category:'紧固件', material:'45#钢', qty:500, min:200, max:1000, unit:'套', price:3.5, location:'B区-04-01', remark:'含螺母垫片', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'INV007', name:'油漆 防锈环氧', spec:'环氧富锌底漆', category:'涂料', material:'环氧树脂', qty:45, min:50, max:100, unit:'kg', price:35, location:'D区-01-01', remark:'灰白色', status:'low', changes:JSON.stringify(['','','',''])},
      {id:'INV008', name:'密封胶 硅酮', spec:'硅酮密封胶', category:'辅材', material:'硅酮', qty:50, min:20, max:100, unit:'支', price:15, location:'D区-02-01', remark:'', status:'enough', changes:JSON.stringify(['','','',''])},
      {id:'INV009', name:'焊接材料 J422', spec:'Φ3.2/Φ4.0', category:'焊接材料', material:'碳钢', qty:0, min:30, max:100, unit:'kg', price:12, location:'D区-03-01', remark:'电焊条', status:'out', changes:JSON.stringify(['','','',''])},
      {id:'INV010', name:'润滑油 L-AN46', spec:'L-AN46', category:'润滑剂', material:'矿物油', qty:30, min:15, max:50, unit:'桶', price:85, location:'D区-04-01', remark:'18L/桶', status:'enough', changes:JSON.stringify(['','','',''])}
    ];
    const stmt = db.prepare("INSERT INTO inventory (id, name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    invs.forEach(i => stmt.run(i.id, i.name, i.spec, i.category, i.material, i.qty, i.min, i.max, i.unit, i.price, i.location, i.remark, i.status, i.changes));
    stmt.finalize();
  });
}

initDemoData();

function initPermissionsAndRoles() {
  const perms = [
    {code:'user:view',name:'查看人员',module:'人员管理'},
    {code:'user:create',name:'添加人员',module:'人员管理'},
    {code:'user:edit',name:'修改人员',module:'人员管理'},
    {code:'user:delete',name:'删除人员',module:'人员管理'},
    {code:'order:view',name:'查看订单',module:'订单管理'},
    {code:'order:create',name:'创建订单',module:'订单管理'},
    {code:'order:edit',name:'修改订单',module:'订单管理'},
    {code:'order:delete',name:'删除订单',module:'订单管理'},
    {code:'bom:view',name:'查看BOM',module:'BOM管理'},
    {code:'bom:create',name:'添加BOM',module:'BOM管理'},
    {code:'bom:edit',name:'修改BOM',module:'BOM管理'},
    {code:'bom:delete',name:'删除BOM',module:'BOM管理'},
    {code:'inventory:view',name:'查看库存',module:'库存管理'},
    {code:'inventory:in',name:'入库操作',module:'库存管理'},
    {code:'inventory:out',name:'出库操作',module:'库存管理'},
    {code:'inventory:edit',name:'修改库存',module:'库存管理'},
    {code:'inventory:delete',name:'删除库存',module:'库存管理'},
    {code:'audit:view',name:'查看审计日志',module:'系统管理'},
    {code:'role:manage',name:'角色权限管理',module:'系统管理'},
    {code:'report:view',name:'查看统计报表',module:'统计分析'}
  ];
  const permStmt = db.prepare("INSERT OR IGNORE INTO permissions (code, name, module, description) VALUES (?, ?, ?, ?)");
  perms.forEach(p => permStmt.run(p.code, p.name, p.module, p.name));
  permStmt.finalize();

  db.get("SELECT COUNT(*) as count FROM roles", (err, row) => {
    if (err || row.count > 0) return;
    const roles = [
      {name:'系统管理员',desc:'全部权限'},
      {name:'部门经理',desc:'管理部门数据'},
      {name:'普通员工',desc:'查看和创建'}
    ];
    const stmt = db.prepare("INSERT INTO roles (name, description, created) VALUES (?, ?, ?)");
    roles.forEach(r => stmt.run(r.name, r.desc, Date.now()));
    stmt.finalize();
  });
}
initPermissionsAndRoles();

// ============ 工具函数 ============
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>]/g, '').trim().slice(0, 500);
}

function auditLog(req, action, target, detail) {
  const user = req.user || {};
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || '';
  db.run("INSERT INTO audit_logs (user_id, user_name, action, target, detail, ip, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [user.id || null, user.name || '', action, target, detail, ip, Date.now()]);
}

// ============ 认证中间件 ============
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未提供令牌' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '令牌无效' });
    req.user = user;
    next();
  });
}

function checkPermission(permissionCode) {
  return (req, res, next) => {
    if (req.user.role === '总经理') return next();
    db.get(`SELECT 1 FROM user_roles ur JOIN role_permissions rp ON ur.role_id = rp.role_id JOIN permissions p ON rp.permission_id = p.id WHERE ur.user_id = ? AND p.code = ? LIMIT 1`, [req.user.id, permissionCode], (err, row) => {
      if (err || !row) return res.status(403).json({ error: '无权限执行此操作' });
      next();
    });
  };
}

// ============ 认证 API ============
app.post('/api/auth/login', (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ error: '缺少参数' });
  if (typeof password !== 'string' || password.length > 100) return res.status(400).json({ error: '参数异常' });

  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      auditLog({ user: { id: userId, name: '未知' } }, '登录失败', 'auth', '用户不存在或ID=' + userId);
      return res.status(401).json({ error: '用户不存在' });
    }
    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match) {
        auditLog({ user: { id: user.id, name: user.name } }, '登录失败', 'auth', '密码错误');
        return res.status(401).json({ error: '密码错误' });
      }
      const token = jwt.sign({ id: user.id, name: user.name, dept: user.dept, role: user.role }, SECRET, { expiresIn: '7d' });
      auditLog({ user: { id: user.id, name: user.name } }, '登录成功', 'auth', '');
      res.json({ token, user: { id: user.id, name: user.name, dept: user.dept, role: user.role } });
    });
  });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// ============ 用户 API ============
app.get('/api/users', authMiddleware, checkPermission('user:view'), (req, res) => {
  db.all("SELECT id, name, dept, role FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', authMiddleware, checkPermission('user:create'), (req, res) => {
  const { id, name, dept, role, password } = req.body;
  if (!name || !dept || !role) return res.status(400).json({ error: '缺少必填字段' });
  const safeName = sanitize(name);
  const safeDept = sanitize(dept);
  const safeRole = sanitize(role);
  const pwd = (typeof password === 'string' && password) ? password : '123456';
  const hash = bcrypt.hashSync(pwd, 10);
  db.run("INSERT INTO users (id, name, dept, role, password) VALUES (?, ?, ?, ?, ?)", [id || Date.now(), safeName, safeDept, safeRole, hash], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '添加人员', 'user', safeName);
    res.json({ id: this.lastID || id });
  });
});

app.put('/api/users/:id', authMiddleware, checkPermission('user:edit'), (req, res) => {
  const { name, dept, role } = req.body;
  if (!name || !dept || !role) return res.status(400).json({ error: '缺少必填字段' });
  const safeName = sanitize(name);
  const safeDept = sanitize(dept);
  const safeRole = sanitize(role);
  db.run("UPDATE users SET name = ?, dept = ?, role = ? WHERE id = ?", [safeName, safeDept, safeRole, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '修改人员', 'user', 'ID=' + req.params.id);
    res.json({ updated: this.changes });
  });
});

app.delete('/api/users/:id', authMiddleware, checkPermission('user:delete'), (req, res) => {
  db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '删除人员', 'user', 'ID=' + req.params.id);
    res.json({ deleted: this.changes });
  });
});

// ============ 订单 API ============
function normalizeProcesses(procs) {
  if (!Array.isArray(procs)) {
    return Array(8).fill(null).map(() => ({ done: false, operator: '', time: '', remark: '', abnormal: '' }));
  }
  if (procs.length > 0 && typeof procs[0] === 'boolean') {
    return procs.map(done => ({ done, operator: done ? '系统迁移' : '', time: done ? new Date().toISOString() : '', remark: '', abnormal: '' }));
  }
  return procs;
}

app.get('/api/orders', authMiddleware, checkPermission('order:view'), (req, res) => {
  db.all("SELECT * FROM orders", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => {
      try { r.processes = normalizeProcesses(JSON.parse(r.processes)); } catch(e) { r.processes = normalizeProcesses(null); }
      try { r.qc = JSON.parse(r.qc); } catch(e) { r.qc = Array(6).fill(false); }
    });
    res.json(rows);
  });
});

app.post('/api/orders', authMiddleware, checkPermission('order:create'), (req, res) => {
  const { id, customer, model, qty, delivery, status, processes, qc, created } = req.body;
  if (!id || !customer || !model) return res.status(400).json({ error: '缺少必填字段' });
  const safeId = sanitize(id);
  const safeCustomer = sanitize(customer);
  const safeModel = sanitize(model);
  const defaultProcs = Array(8).fill(null).map(() => ({ done: false, operator: '', time: '', remark: '', abnormal: '' }));
  const procs = JSON.stringify(processes || defaultProcs);
  const qcs = JSON.stringify(qc || Array(6).fill(false));
  db.run("INSERT INTO orders (id, customer, model, qty, delivery, status, processes, qc, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [safeId, safeCustomer, safeModel, qty || 1, delivery, status || 'pending', procs, qcs, created || new Date().toISOString()],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      auditLog(req, '创建订单', 'order', safeId);
      res.json({ id: safeId });
    });
});

app.put('/api/orders/:id', authMiddleware, checkPermission('order:edit'), (req, res) => {
  const { customer, model, qty, delivery, status, processes, qc } = req.body;
  const safeCustomer = customer ? sanitize(customer) : undefined;
  const safeModel = model ? sanitize(model) : undefined;
  const procs = processes ? JSON.stringify(processes) : undefined;
  const qcs = qc ? JSON.stringify(qc) : undefined;
  db.run("UPDATE orders SET customer = COALESCE(?, customer), model = COALESCE(?, model), qty = COALESCE(?, qty), delivery = COALESCE(?, delivery), status = COALESCE(?, status), processes = COALESCE(?, processes), qc = COALESCE(?, qc) WHERE id = ?",
    [safeCustomer, safeModel, qty, delivery, status, procs, qcs, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      auditLog(req, '修改订单', 'order', 'ID=' + req.params.id);
      res.json({ updated: this.changes });
    });
});

app.delete('/api/orders/:id', authMiddleware, checkPermission('order:delete'), (req, res) => {
  db.run("DELETE FROM orders WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '删除订单', 'order', 'ID=' + req.params.id);
    res.json({ deleted: this.changes });
  });
});

// ============ 统计报表 API ============
app.get('/api/reports', authMiddleware, checkPermission('report:view'), (req, res) => {
  const report = { orders: {}, production: {}, inventory: {}, staff: [] };

  // 订单统计
  db.all("SELECT status, COUNT(*) as count FROM orders GROUP BY status", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const byStatus = {};
    let total = 0;
    rows.forEach(r => { byStatus[r.status] = r.count; total += r.count; });
    report.orders.total = total;
    report.orders.byStatus = byStatus;

    db.all("SELECT strftime('%Y-%m', created) as month, COUNT(*) as count FROM orders GROUP BY month ORDER BY month", [], (err, rows2) => {
      if (err) return res.status(500).json({ error: err.message });
      report.orders.monthly = rows2;

      // 库存统计
      db.all("SELECT status, COUNT(*) as count FROM inventory GROUP BY status", [], (err, rows3) => {
        if (err) return res.status(500).json({ error: err.message });
        const invStats = {};
        rows3.forEach(r => { invStats[r.status] = r.count; });
        report.inventory = invStats;

        // 生产工序统计（从订单 processes 字段解析）
        db.all("SELECT processes FROM orders", [], (err, rows4) => {
          if (err) return res.status(500).json({ error: err.message });
          const processStats = Array(8).fill(0);
          const staffMap = {};
          rows4.forEach(r => {
            try {
              const procs = normalizeProcesses(JSON.parse(r.processes));
              procs.forEach((p, idx) => {
                if (p.done) processStats[idx]++;
                if (p.done && p.operator) {
                  staffMap[p.operator] = (staffMap[p.operator] || 0) + 1;
                }
              });
            } catch(e) {}
          });
          report.production.processCompletion = processStats.map((count, idx) => ({
            name: ['机壳拼焊','底座拼焊','机壳底座焊接','叶轮拼焊','叶轮焊接','喷砂油漆','风机组装','测试出厂'][idx],
            completed: count,
            total: rows4.length
          }));

          // 人员工作量排序
          report.staff = Object.entries(staffMap)
            .map(([name, count]) => ({ name, processCount: count }))
            .sort((a, b) => b.processCount - a.processCount)
            .slice(0, 20);

          res.json(report);
        });
      });
    });
  });
});

// ============ BOM API ============
app.get('/api/bom', authMiddleware, checkPermission('bom:view'), (req, res) => {
  db.all("SELECT * FROM bom", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => {
      try { r.changes = JSON.parse(r.changes); } catch(e) { r.changes = ['','','','']; }
    });
    res.json(rows);
  });
});

app.post('/api/bom', authMiddleware, checkPermission('bom:create'), (req, res) => {
  const { id, code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes } = req.body;
  if (!id || !name) return res.status(400).json({ error: '缺少必填字段' });
  const safeName = sanitize(name);
  db.run("INSERT INTO bom (id, code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [id, code, model, safeName, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status || 'enough', JSON.stringify(changes || ['','','',''])],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      auditLog(req, '添加BOM', 'bom', id);
      res.json({ id });
    });
});

app.put('/api/bom/:id', authMiddleware, checkPermission('bom:edit'), (req, res) => {
  const { code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes } = req.body;
  const safeName = name ? sanitize(name) : undefined;
  const chg = changes ? JSON.stringify(changes) : undefined;
  db.run("UPDATE bom SET code = COALESCE(?, code), model = COALESCE(?, model), name = COALESCE(?, name), qty = COALESCE(?, qty), material = COALESCE(?, material), unitWeight = COALESCE(?, unitWeight), totalWeight = COALESCE(?, totalWeight), unit = COALESCE(?, unit), manufacturer = COALESCE(?, manufacturer), remark = COALESCE(?, remark), status = COALESCE(?, status), changes = COALESCE(?, changes) WHERE id = ?",
    [code, model, safeName, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, chg, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      auditLog(req, '修改BOM', 'bom', 'ID=' + req.params.id);
      res.json({ updated: this.changes });
    });
});

app.delete('/api/bom/:id', authMiddleware, checkPermission('bom:delete'), (req, res) => {
  db.run("DELETE FROM bom WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '删除BOM', 'bom', 'ID=' + req.params.id);
    res.json({ deleted: this.changes });
  });
});

// ============ 库存 API ============
app.get('/api/inventory', authMiddleware, checkPermission('inventory:view'), (req, res) => {
  db.all("SELECT * FROM inventory", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => {
      try { r.changes = JSON.parse(r.changes); } catch(e) { r.changes = ['','','','']; }
    });
    res.json(rows);
  });
});

app.post('/api/inventory', authMiddleware, checkPermission('inventory:edit'), (req, res) => {
  const { id, name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes } = req.body;
  if (!id || !name) return res.status(400).json({ error: '缺少必填字段' });
  const safeName = sanitize(name);
  db.run("INSERT INTO inventory (id, name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [id, safeName, spec, category, material, qty, min, max, unit, price, location, remark, status || 'enough', JSON.stringify(changes || ['','','',''])],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      auditLog(req, '添加库存', 'inventory', id);
      res.json({ id });
    });
});

app.put('/api/inventory/:id', authMiddleware, checkPermission('inventory:edit'), (req, res) => {
  const { name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes } = req.body;
  const safeName = name ? sanitize(name) : undefined;
  const chg = changes ? JSON.stringify(changes) : undefined;
  db.run("UPDATE inventory SET name = COALESCE(?, name), spec = COALESCE(?, spec), category = COALESCE(?, category), material = COALESCE(?, material), qty = COALESCE(?, qty), min = COALESCE(?, min), max = COALESCE(?, max), unit = COALESCE(?, unit), price = COALESCE(?, price), location = COALESCE(?, location), remark = COALESCE(?, remark), status = COALESCE(?, status), changes = COALESCE(?, changes) WHERE id = ?",
    [safeName, spec, category, material, qty, min, max, unit, price, location, remark, status, chg, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      auditLog(req, '修改库存', 'inventory', 'ID=' + req.params.id);
      res.json({ updated: this.changes });
    });
});

app.delete('/api/inventory/:id', authMiddleware, checkPermission('inventory:delete'), (req, res) => {
  db.run("DELETE FROM inventory WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '删除库存', 'inventory', 'ID=' + req.params.id);
    res.json({ deleted: this.changes });
  });
});

app.get('/api/inventory/logs', authMiddleware, (req, res) => {
  db.all("SELECT * FROM inv_logs ORDER BY time DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/inventory/in', authMiddleware, checkPermission('inventory:in'), (req, res) => {
  const { itemId, qty, remark } = req.body;
  if (!itemId || typeof qty !== 'number' || qty <= 0) return res.status(400).json({ error: '参数错误' });
  db.get("SELECT * FROM inventory WHERE id = ?", [itemId], (err, item) => {
    if (err || !item) return res.status(404).json({ error: '物料不存在' });
    const newQty = item.qty + qty;
    db.run("UPDATE inventory SET qty = ? WHERE id = ?", [newQty, itemId], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run("INSERT INTO inv_logs (item_id, type, item_name, qty, remark, time) VALUES (?, ?, ?, ?, ?, ?)",
        [itemId, 'in', item.name, qty, remark || '入库', Date.now()]);
      auditLog(req, '入库', 'inventory', `${item.name} +${qty}`);
      res.json({ success: true, qty: newQty });
    });
  });
});

app.post('/api/inventory/out', authMiddleware, checkPermission('inventory:out'), (req, res) => {
  const { itemId, qty, remark } = req.body;
  if (!itemId || typeof qty !== 'number' || qty <= 0) return res.status(400).json({ error: '参数错误' });
  db.get("SELECT * FROM inventory WHERE id = ?", [itemId], (err, item) => {
    if (err || !item) return res.status(404).json({ error: '物料不存在' });
    if (item.qty < qty) return res.status(400).json({ error: '库存不足' });
    const newQty = item.qty - qty;
    db.run("UPDATE inventory SET qty = ? WHERE id = ?", [newQty, itemId], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run("INSERT INTO inv_logs (item_id, type, item_name, qty, remark, time) VALUES (?, ?, ?, ?, ?, ?)",
        [itemId, 'out', item.name, qty, remark || '出库', Date.now()]);
      auditLog(req, '出库', 'inventory', `${item.name} -${qty}`);
      res.json({ success: true, qty: newQty });
    });
  });
});

app.get('/api/audit-logs', authMiddleware, checkPermission('audit:view'), (req, res) => {
  db.all("SELECT * FROM audit_logs ORDER BY time DESC LIMIT 500", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ============ RBAC API ============
app.get('/api/roles', authMiddleware, checkPermission('role:manage'), (req, res) => {
  db.all("SELECT * FROM roles", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/roles', authMiddleware, checkPermission('role:manage'), (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: '缺少角色名称' });
  db.run("INSERT INTO roles (name, description, created) VALUES (?, ?, ?)", [sanitize(name), sanitize(description), Date.now()], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '创建角色', 'role', sanitize(name));
    res.json({ id: this.lastID });
  });
});

app.put('/api/roles/:id', authMiddleware, checkPermission('role:manage'), (req, res) => {
  const { name, description } = req.body;
  db.run("UPDATE roles SET name = COALESCE(?, name), description = COALESCE(?, description) WHERE id = ?", [name ? sanitize(name) : null, description ? sanitize(description) : null, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    auditLog(req, '修改角色', 'role', 'ID=' + req.params.id);
    res.json({ updated: this.changes });
  });
});

app.delete('/api/roles/:id', authMiddleware, checkPermission('role:manage'), (req, res) => {
  db.run("DELETE FROM roles WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run("DELETE FROM role_permissions WHERE role_id = ?", [req.params.id]);
    db.run("DELETE FROM user_roles WHERE role_id = ?", [req.params.id]);
    auditLog(req, '删除角色', 'role', 'ID=' + req.params.id);
    res.json({ deleted: this.changes });
  });
});

app.get('/api/permissions', authMiddleware, (req, res) => {
  db.all("SELECT * FROM permissions ORDER BY module, code", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/roles/:id/permissions', authMiddleware, checkPermission('role:manage'), (req, res) => {
  db.all("SELECT p.* FROM permissions p JOIN role_permissions rp ON p.id = rp.permission_id WHERE rp.role_id = ?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/roles/:id/permissions', authMiddleware, checkPermission('role:manage'), (req, res) => {
  const { permissionIds } = req.body;
  if (!Array.isArray(permissionIds)) return res.status(400).json({ error: '参数错误' });
  db.run("DELETE FROM role_permissions WHERE role_id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    const stmt = db.prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)");
    permissionIds.forEach(pid => stmt.run(req.params.id, pid));
    stmt.finalize();
    auditLog(req, '配置角色权限', 'role', 'RoleID=' + req.params.id);
    res.json({ success: true });
  });
});

app.get('/api/users/:id/roles', authMiddleware, checkPermission('role:manage'), (req, res) => {
  db.all("SELECT r.* FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users/:id/roles', authMiddleware, checkPermission('role:manage'), (req, res) => {
  const { roleIds } = req.body;
  if (!Array.isArray(roleIds)) return res.status(400).json({ error: '参数错误' });
  db.run("DELETE FROM user_roles WHERE user_id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    const stmt = db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
    roleIds.forEach(rid => stmt.run(req.params.id, rid));
    stmt.finalize();
    auditLog(req, '分配用户角色', 'user', 'UserID=' + req.params.id);
    res.json({ success: true });
  });
});

app.get('/api/my-permissions', authMiddleware, (req, res) => {
  if (req.user.role === '总经理') {
    db.all("SELECT code FROM permissions", [], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows.map(r => r.code));
    });
  } else {
    db.all("SELECT DISTINCT p.code FROM permissions p JOIN role_permissions rp ON p.id = rp.permission_id JOIN user_roles ur ON rp.role_id = ur.role_id WHERE ur.user_id = ?", [req.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows.map(r => r.code));
    });
  }
});

// ============ 静态文件 & 启动 ============
const publicPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(publicPath));

app.listen(PORT, () => {
  console.log(`巴法洛风机管理系统后端运行在 http://localhost:${PORT}`);
  console.log(`数据库: ${dbPath}`);
});
