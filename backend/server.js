const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'buffalo-fan-secret-key-2024';

app.use(cors());
app.use(express.json());

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

// ============ 认证中间件 ============
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未提供令牌' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '令牌无效' });
    req.user = user;
    next();
  });
}

// ============ 认证 API ============
app.post('/api/auth/login', (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ error: '缺少参数' });

  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) return res.status(401).json({ error: '用户不存在' });
    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match) return res.status(401).json({ error: '密码错误' });
      const token = jwt.sign({ id: user.id, name: user.name, dept: user.dept, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: { id: user.id, name: user.name, dept: user.dept, role: user.role } });
    });
  });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// ============ 用户 API ============
app.get('/api/users', authMiddleware, (req, res) => {
  db.all("SELECT id, name, dept, role FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', authMiddleware, (req, res) => {
  const { id, name, dept, role, password } = req.body;
  const pwd = password || '123456';
  const hash = bcrypt.hashSync(pwd, 10);
  db.run("INSERT INTO users (id, name, dept, role, password) VALUES (?, ?, ?, ?, ?)", [id || Date.now(), name, dept, role, hash], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID || id });
  });
});

app.put('/api/users/:id', authMiddleware, (req, res) => {
  const { name, dept, role } = req.body;
  db.run("UPDATE users SET name = ?, dept = ?, role = ? WHERE id = ?", [name, dept, role, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: this.changes });
  });
});

app.delete('/api/users/:id', authMiddleware, (req, res) => {
  db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// ============ 订单 API ============
app.get('/api/orders', authMiddleware, (req, res) => {
  db.all("SELECT * FROM orders", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => {
      try { r.processes = JSON.parse(r.processes); } catch(e) { r.processes = Array(8).fill(false); }
      try { r.qc = JSON.parse(r.qc); } catch(e) { r.qc = Array(6).fill(false); }
    });
    res.json(rows);
  });
});

app.post('/api/orders', authMiddleware, (req, res) => {
  const { id, customer, model, qty, delivery, status, processes, qc, created } = req.body;
  const procs = JSON.stringify(processes || Array(8).fill(false));
  const qcs = JSON.stringify(qc || Array(6).fill(false));
  db.run("INSERT INTO orders (id, customer, model, qty, delivery, status, processes, qc, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [id, customer, model, qty || 1, delivery, status || 'pending', procs, qcs, created || new Date().toISOString()],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id });
    });
});

app.put('/api/orders/:id', authMiddleware, (req, res) => {
  const { customer, model, qty, delivery, status, processes, qc } = req.body;
  const procs = processes ? JSON.stringify(processes) : undefined;
  const qcs = qc ? JSON.stringify(qc) : undefined;
  db.run("UPDATE orders SET customer = ?, model = ?, qty = ?, delivery = ?, status = ?, processes = COALESCE(?, processes), qc = COALESCE(?, qc) WHERE id = ?",
    [customer, model, qty, delivery, status, procs, qcs, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
});

app.delete('/api/orders/:id', authMiddleware, (req, res) => {
  db.run("DELETE FROM orders WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// ============ BOM API ============
app.get('/api/bom', authMiddleware, (req, res) => {
  db.all("SELECT * FROM bom", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => {
      try { r.changes = JSON.parse(r.changes); } catch(e) { r.changes = ['','','','']; }
    });
    res.json(rows);
  });
});

app.post('/api/bom', authMiddleware, (req, res) => {
  const { id, code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes } = req.body;
  db.run("INSERT INTO bom (id, code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [id, code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status || 'enough', JSON.stringify(changes || ['','','',''])],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id });
    });
});

app.put('/api/bom/:id', authMiddleware, (req, res) => {
  const { code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, changes } = req.body;
  const chg = changes ? JSON.stringify(changes) : undefined;
  db.run("UPDATE bom SET code = ?, model = ?, name = ?, qty = ?, material = ?, unitWeight = ?, totalWeight = ?, unit = ?, manufacturer = ?, remark = ?, status = ?, changes = COALESCE(?, changes) WHERE id = ?",
    [code, model, name, qty, material, unitWeight, totalWeight, unit, manufacturer, remark, status, chg, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
});

app.delete('/api/bom/:id', authMiddleware, (req, res) => {
  db.run("DELETE FROM bom WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// ============ 库存 API ============
app.get('/api/inventory', authMiddleware, (req, res) => {
  db.all("SELECT * FROM inventory", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => {
      try { r.changes = JSON.parse(r.changes); } catch(e) { r.changes = ['','','','']; }
    });
    res.json(rows);
  });
});

app.post('/api/inventory', authMiddleware, (req, res) => {
  const { id, name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes } = req.body;
  db.run("INSERT INTO inventory (id, name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [id, name, spec, category, material, qty, min, max, unit, price, location, remark, status || 'enough', JSON.stringify(changes || ['','','',''])],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id });
    });
});

app.put('/api/inventory/:id', authMiddleware, (req, res) => {
  const { name, spec, category, material, qty, min, max, unit, price, location, remark, status, changes } = req.body;
  const chg = changes ? JSON.stringify(changes) : undefined;
  db.run("UPDATE inventory SET name = ?, spec = ?, category = ?, material = ?, qty = ?, min = ?, max = ?, unit = ?, price = ?, location = ?, remark = ?, status = ?, changes = COALESCE(?, changes) WHERE id = ?",
    [name, spec, category, material, qty, min, max, unit, price, location, remark, status, chg, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
});

app.delete('/api/inventory/:id', authMiddleware, (req, res) => {
  db.run("DELETE FROM inventory WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

app.get('/api/inventory/logs', authMiddleware, (req, res) => {
  db.all("SELECT * FROM inv_logs ORDER BY time DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/inventory/in', authMiddleware, (req, res) => {
  const { itemId, qty, remark } = req.body;
  db.get("SELECT * FROM inventory WHERE id = ?", [itemId], (err, item) => {
    if (err || !item) return res.status(404).json({ error: '物料不存在' });
    const newQty = item.qty + qty;
    db.run("UPDATE inventory SET qty = ? WHERE id = ?", [newQty, itemId], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run("INSERT INTO inv_logs (item_id, type, item_name, qty, remark, time) VALUES (?, ?, ?, ?, ?, ?)",
        [itemId, 'in', item.name, qty, remark || '入库', Date.now()]);
      res.json({ success: true, qty: newQty });
    });
  });
});

app.post('/api/inventory/out', authMiddleware, (req, res) => {
  const { itemId, qty, remark } = req.body;
  db.get("SELECT * FROM inventory WHERE id = ?", [itemId], (err, item) => {
    if (err || !item) return res.status(404).json({ error: '物料不存在' });
    if (item.qty < qty) return res.status(400).json({ error: '库存不足' });
    const newQty = item.qty - qty;
    db.run("UPDATE inventory SET qty = ? WHERE id = ?", [newQty, itemId], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run("INSERT INTO inv_logs (item_id, type, item_name, qty, remark, time) VALUES (?, ?, ?, ?, ?, ?)",
        [itemId, 'out', item.name, qty, remark || '出库', Date.now()]);
      res.json({ success: true, qty: newQty });
    });
  });
});

// ============ 静态文件 & 启动 ============
const publicPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(publicPath));

app.listen(PORT, () => {
  console.log(`巴法洛风机管理系统后端运行在 http://localhost:${PORT}`);
  console.log(`数据库: ${dbPath}`);
});
