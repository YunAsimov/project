const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, HeadingLevel, BorderStyle, WidthType,
  ShadingType, ImageRun, PageNumber, Footer, Header, TableOfContents, PageBreak,
} = require('docx');

const IMG = path.join(__dirname, 'diagrams_png');
const CONTENT_W = 9026; // A4, 1" margins

// ---------- helpers ----------
const FONT = "Microsoft YaHei";
const MONO = "Consolas";

function P(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 120, line: 300 },
    children: [new TextRun({ text, ...opts })],
    ...(opts.para || {}),
  });
}
function runs(children, opts = {}) {
  return new Paragraph({ spacing: { after: 120, line: 300 }, children, ...opts });
}
function H1(text) { return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] }); }
function H2(text) { return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] }); }
function H3(text) { return new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(text)] }); }

function bullet(text, level = 0) {
  return new Paragraph({
    numbering: { reference: "bullets", level },
    spacing: { after: 60, line: 290 },
    children: [new TextRun(text)],
  });
}

function codeBlock(code) {
  const lines = code.replace(/\n$/, '').split('\n');
  return lines.map((ln, i) => new Paragraph({
    shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
    spacing: { after: 0, before: 0, line: 250 },
    border: {
      left: { style: BorderStyle.SINGLE, size: 18, color: "D0D7DE", space: 6 },
    },
    indent: { left: 120 },
    children: [new TextRun({ text: ln || " ", font: MONO, size: 18, color: "24292F" })],
  }));
}

async function image(file, captionText) {
  const full = path.join(IMG, file);
  const meta = await sharp(full).metadata();
  const w = 560;
  const h = Math.round(w * meta.height / meta.width);
  const para = new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 120, after: 60 },
    children: [new ImageRun({
      type: "png", data: fs.readFileSync(full),
      transformation: { width: w, height: h },
      altText: { title: captionText, description: captionText, name: file },
    })],
  });
  const cap = new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 180 },
    children: [new TextRun({ text: captionText, italics: true, size: 18, color: "656D76" })],
  });
  return [para, cap];
}

const BD = { style: BorderStyle.SINGLE, size: 1, color: "C9D1D9" };
const BORDERS = { top: BD, bottom: BD, left: BD, right: BD, insideHorizontal: BD, insideVertical: BD };

function cell(text, w, { head = false, bold = false } = {}) {
  const parts = Array.isArray(text) ? text : [text];
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    borders: { top: BD, bottom: BD, left: BD, right: BD },
    shading: head ? { type: ShadingType.CLEAR, fill: "EAEEF2" } : undefined,
    margins: { top: 60, bottom: 60, left: 110, right: 110 },
    children: parts.map(t => new Paragraph({
      spacing: { after: 0, line: 270 },
      children: [new TextRun({ text: t, bold: head || bold, size: 19 })],
    })),
  });
}

function table(headers, rows, widths) {
  const trHead = new TableRow({
    tableHeader: true,
    children: headers.map((h, i) => cell(h, widths[i], { head: true })),
  });
  const trBody = rows.map(r => new TableRow({
    children: r.map((c, i) => cell(c, widths[i])),
  }));
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: widths,
    borders: BORDERS,
    rows: [trHead, ...trBody],
  });
}

(async () => {
  const children = [];

  // ---------- cover ----------
  children.push(new Paragraph({ spacing: { before: 2400, after: 0 } }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "端到端加密一对一消息系统", bold: true, size: 56 })],
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 600 },
    children: [new TextRun({ text: "设计与实现技术报告", size: 32, color: "57606A" })],
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 80 },
    children: [new TextRun({ text: "COMP 5355 Cyber and Internet Security  2025/2026", size: 24 })],
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 80 },
    children: [new TextRun({ text: "任务一:端到端加密(E2EE)消息系统", size: 24 })],
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 1200 },
    children: [new TextRun({ text: "小组报告(中文版)", size: 24, color: "57606A" })],
  }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ---------- TOC ----------
  children.push(new Paragraph({ spacing: { after: 200 }, children: [new TextRun({ text: "目录", bold: true, size: 32 })] }));
  children.push(new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-3" }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ====================================================================
  children.push(H1("1  摘要"));
  children.push(P("本项目设计并实现了一个端到端加密(E2EE)的一对一文本消息系统。系统的核心安全原则是:明文仅存在于两个通信端点;中继服务器与底层网络只接触密文以及路由所需的最小元数据。系统完整实现了任务要求的三项必需功能——用户注册与密钥生成、认证密钥交换与会话建立、收发文本消息——并满足机密性、完整性、真实性、防重放(SR1–SR4)。"));
  children.push(P("在此基础上,系统进一步覆盖了两项加分目标:B1 前向保密(每会话使用一次性临时密钥)与 B2 恶意服务器抵抗(基于带外安全号比对)。项目以 Python 实现 CLI 客户端与中继服务器,并额外提供了一个浏览器前端;前端采用「本地桥接」架构,在不破坏端到端安全模型的前提下提供注册、登录(密码经 scrypt 加盐哈希存入 MySQL)与发消息的图形界面。"));
  children.push(P("全部低层密码学原语均来自经审计的 cryptography 库,未自行实现任何原语。代码附带 68 个自动化测试(含一个真实 WebSocket 全栈集成测试),并通过浏览器实测验证了网页端的完整收发流程。"));

  // ====================================================================
  children.push(H1("2  系统设计与威胁模型"));
  children.push(H2("2.1  系统架构"));
  children.push(P("系统由三个实体组成:发送端(客户端 A)、接收端(客户端 B)与中继服务器。发送端与接收端各自生成并管理自己的密钥对,通过服务器交换公钥,再经认证密钥交换建立会话密钥;消息在发送端加密、经服务器转发、在接收端解密。"));
  (await image("system_architecture.png", "图 1  系统架构与信任边界")).forEach(p => children.push(p));
  children.push(P("各实体的角色与信任级别如下:"));
  children.push(bullet("客户端(唯一信任锚):生成与保管密钥、加解密消息、验证消息合法性。明文与会话密钥永不离开客户端。"));
  children.push(bullet("中继服务器(弱信任,honest-but-curious):提供注册、公钥分发、按路由转发三项服务;它能读取所经手的一切,但所见仅限密文与路由元数据。"));
  children.push(bullet("网络(完全不可信):不提供任何机密性、完整性或真实性,全部安全属性必须由端点以密码学手段建立。"));

  children.push(H2("2.2  信任边界与假设"));
  children.push(table(
    ["组件", "信任级别", "说明"],
    [
      ["端点", "完全信任", "正确执行协议,妥善保管长期与会话密钥;基础模型下端点不被攻陷。"],
      ["服务器", "弱信任(A3)", "忠实执行协议但会记录所见的一切;设计须保证其学不到明文。"],
      ["网络", "不信任(A1/A2)", "链路被对手完全控制。"],
      ["密码学原语", "信任", "Ed25519、X25519、HKDF、ChaCha20-Poly1305 假定安全。"],
    ],
    [1600, 1900, 5526],
  ));
  children.push(P("关于公钥分发:服务器存储并分发用户身份公钥。基础模型下服务器会分发正确的公钥,但客户端与服务器之间的信道仍可能被主动网络攻击者(A2)操纵。本系统不依赖 TLS 等传输层机制来保护此信道——握手中的身份签名使得即便公钥在传输中被替换,验签也会失败(见第 7 节)。", { para: { spacing: { before: 120, after: 120, line: 300 } } }));

  children.push(H2("2.3  威胁模型(对手分类)"));
  children.push(table(
    ["编号", "对手", "能力"],
    [
      ["A1", "被动网络攻击者", "观察并记录全部传输数据(密文、时序、大小、收发地址)。"],
      ["A2", "主动网络攻击者", "A1 全部能力 + 修改/丢弃/延迟/重排/重放/注入,并可在握手时尝试中间人(MitM)。"],
      ["A3", "honest-but-curious 服务器", "忠实执行协议,但对存储与转发的一切有完全读取权限。"],
      ["A4(加分)", "瞬时端点泄露", "某一时刻读取一台设备的秘密状态(含长期私钥),随后失去访问。"],
      ["A5(加分)", "恶意服务器", "A3 + 不必遵守协议:可篡改/丢弃/注入数据,可分发假公钥实施中间人。"],
    ],
    [1300, 2400, 5326],
  ));

  children.push(H2("2.4  安全要求"));
  children.push(table(
    ["编号", "要求", "含义"],
    [
      ["SR1", "机密性", "仅授权用户能访问明文;被动观察者/服务器至多学到密文长度等显式允许的泄漏。"],
      ["SR2", "完整性", "任何对密文的修改/替换/伪造都被接收方以压倒性概率检测并拒绝。"],
      ["SR3", "消息与发送者真实性", "接收方能验证消息确实来自所声称的发送者,未被第三方伪造或注入。"],
      ["SR4", "防重放", "攻击者重发截获的合法消息无法产生重复效果。"],
      ["SR5(加分)", "前向保密", "长期私钥泄露不危及过去会话的机密性。"],
      ["SR6(加分)", "恶意服务器抵抗", "服务器停止遵守协议时,完整性(SR2)仍成立。"],
    ],
    [1300, 2200, 5526],
  ));

  children.push(H2("2.5  明确的范围外"));
  children.push(bullet("可用性:无限期丢弃/延迟流量的拒绝服务攻击不在范围内。"));
  children.push(bullet("持久端点攻陷:攻击者持续控制使用中的设备不在范围内(A4 仅为一次性泄露)。"));
  children.push(bullet("元数据隐私:路由所需的收发方身份、消息大小、时序对服务器可见,属显式允许泄漏。"));
  children.push(bullet("客户端-服务器认证:按任务说明保持简单,不是本项目重点。"));

  // ====================================================================
  children.push(H1("3  密码学选型与参数"));
  children.push(P("全部原语取自 Python cryptography 库;设计工作是「组合标准原语」,而非发明新原语。选型与参数如下:"));
  children.push(table(
    ["用途", "原语 / 参数", "选型理由"],
    [
      ["身份签名", "Ed25519", "确定性、抗侧信道、公钥仅 32 字节;用于对握手 transcript 签名以确立身份。"],
      ["密钥协商", "X25519(临时)", "现代 ECDH,实现简单且安全;每会话一次性使用以提供前向保密。"],
      ["密钥派生", "HKDF-SHA256", "从共享秘密派生均匀密钥;info 标签绑定用途与方向,salt 绑定本次握手。"],
      ["认证加密", "ChaCha20-Poly1305", "AEAD,软件实现快且抗时序攻击;128 位标签提供完整性与真实性。"],
      ["口令哈希", "scrypt(N=16384,r=8,p=1)", "内存难解 KDF(标准库内置),加每用户随机盐,抵抗暴力与彩虹表。"],
    ],
    [1700, 2700, 4626],
  ));
  children.push(P("关键纪律:① 所有随机量来自库 CSPRNG(os.urandom);② nonce 在同一密钥下绝不重用;③ X25519 原始共享秘密绝不直接当密钥,一律经 HKDF;④ 网络上不出现任何明文密钥。", { para: { spacing: { before: 120, after: 120, line: 300 } } }));

  // ====================================================================
  children.push(H1("4  协议设计"));

  children.push(H2("4.1  密钥类型与生命周期"));
  children.push(table(
    ["密钥", "算法", "生命周期", "用途"],
    [
      ["长期身份密钥", "Ed25519", "注册时生成,本地长期保存", "对握手 transcript 签名,确立身份"],
      ["临时密钥", "X25519", "每次会话生成,握手后即弃", "密钥协商(提供前向保密)"],
      ["会话方向密钥", "HKDF 派生", "会话期间(每方向各一)", "AEAD 加解密"],
    ],
    [2200, 1500, 2800, 2526],
  ));
  children.push(P("身份私钥以 32 字节原始形式存于本地 keystore(0600 权限,并经 .gitignore 排除),永不上传服务器。", { para: { spacing: { before: 120, after: 120, line: 300 } } }));

  children.push(H2("4.2  报文格式"));
  children.push(P("采用 UTF-8 JSON,二进制字段以 base64 编码。每类报文均带 type 与 version。服务器只读取 from/to 路由字段;eph_pub、signature、nonce、ciphertext 对服务器不透明。"));
  children.push(...codeBlock(
`register       { type, version, username, identity_pub }
lookup         { type, version, username }
lookup_result  { type, version, username, identity_pub | found:false }
hs_init        { type, version, from, to, session_id, eph_pub, signature }
hs_resp        { type, version, from, to, session_id, eph_pub, signature }
data           { type, version, from, to, session_id, counter, nonce, ciphertext }
error          { type, version, reason, ref? }   # 服务器控制/诊断消息`));

  children.push(H2("4.3  认证握手"));
  children.push(P("握手在「发起方」(主动发起聊天者)与「响应方」之间进行,目标是在防中间人的前提下协商出会话密钥,同时提供前向保密。完整时序如下:"));
  (await image("handshake_sequence.png", "图 2  认证握手与消息流时序")).forEach(p => children.push(p));
  children.push(P("签名材料(transcript)采用长度前缀拼接(每段前置 4 字节大端长度),消除字段边界歧义;两条 transcript 各带不同域标签,防止跨消息混淆。其构造为:"));
  children.push(...codeBlock(
`T_init = LP("comp5355-hs-init-v1", session_id,
            发起方身份公钥, 响应方身份公钥, 发起方临时公钥)

T_resp = LP("comp5355-hs-resp-v1", session_id,
            响应方身份公钥, 发起方身份公钥,
            发起方临时公钥, 响应方临时公钥)   # 额外绑定发起方临时公钥`));
  children.push(P("两条签名都覆盖双方身份公钥,可防身份误绑定 / 未知密钥共享(UKS)攻击;响应方签名额外覆盖发起方的临时公钥,把整个握手绑死,防止反射/重放。会话密钥由 X25519 共享秘密经 HKDF 派生为两把方向密钥:"));
  children.push(...codeBlock(
`shared = X25519(自己临时私钥, 对方临时公钥)
salt   = 发起方临时公钥 || 响应方临时公钥
k_i2r  = HKDF-SHA256(shared, salt, info = "comp5355-e2ee/session-key/v1|i2r")
k_r2i  = HKDF-SHA256(shared, salt, info = "comp5355-e2ee/session-key/v1|r2i")
# 发起方:发用 k_i2r、收用 k_r2i;响应方相反`));
  children.push(P("派生两把方向密钥至关重要:若两个方向共用一把密钥且各自计数器都从 0 开始,nonce 将重用,对 AEAD 是灾难性的。分方向派生从根本上避免该问题。前向保密(B1)来自临时私钥在握手后即被丢弃——日后即便泄露长期身份私钥,也无法重算任何过去会话的共享秘密。"));

  children.push(H2("4.4  消息加密与解密"));
  children.push(P("应用消息使用方向密钥进行 AEAD 加密。关联数据(AD)绑定路由与顺序上下文,使一段密文只在唯一的方向、会话与位置上有效。"));
  (await image("message_flow.png", "图 3  消息加密 / 解密流程")).forEach(p => children.push(p));
  children.push(P("AD 采用 0x1f 作为分隔符,杜绝拼接歧义(例如 (\"ab\",\"c\") 与 (\"a\",\"bc\") 产生不同 AD);nonce 由方向内单调计数器派生:"));
  children.push(...codeBlock(
`# 发送
counter = session.next_send_counter()         # 单调递增
nonce   = counter.to_bytes(12, "big")          # 每方向独立密钥 → nonce 永不重用
AD      = from || 0x1f || to || 0x1f || session_id || 0x1f || str(counter)
ciphertext = ChaCha20Poly1305(send_key).encrypt(nonce, plaintext, AD)

# 接收(顺序严格)
1) 路由检查:session_id、from/to 必须匹配本会话
2) AEAD 验签解密:用 recv_key 与重建的 AD;失败即拒        (SR2 / SR3)
3) 重放窗口检查:counter 经滑动窗口校验;重复或越窗即拒     (SR4)`));
  children.push(P("关键顺序是「先验 AEAD 标签,后更新重放窗口」。若顺序相反,攻击者发一个高 counter 的伪造帧即可污染窗口、使后续合法消息被误拒。本实现通过该顺序避免此问题(对应测试 test_forged_counter_does_not_poison_window)。"));

  children.push(H2("4.5  防重放滑动窗口"));
  children.push(P("接收方维护「最高已见计数器」与一个 RFC 6479 风格的滑动位图窗口(窗口大小 64)。判定规则如下图:"));
  (await image("replay_window.png", "图 4  防重放滑动窗口")).forEach(p => children.push(p));
  children.push(P("核心判定逻辑(摘自 client/session.py):"));
  children.push(...codeBlock(
`def accept_recv_counter(self, counter):
    if counter < 0: return False
    if counter > self._recv_highest:           # 新最高:窗口前移
        shift = counter - self._recv_highest
        self._recv_bitmap = (self._recv_bitmap << shift) & mask if shift < W else 0
        self._recv_bitmap |= 1                  # 标记新最高为已见
        self._recv_highest = counter
        return True
    offset = self._recv_highest - counter
    if offset >= W:               return False  # 越窗(过旧)
    if self._recv_bitmap & (1<<offset): return False  # 重放(已见)
    self._recv_bitmap |= (1 << offset)          # 窗口内未见:接受
    return True`));

  // ====================================================================
  children.push(H1("5  实现与代码结构"));
  children.push(P("项目以 Python 实现,模块按职责清晰划分:"));
  children.push(...codeBlock(
`crypto/     原语薄封装(primitives.py:签名/ECDH/HKDF/AEAD;fingerprint.py:安全号)
protocol/   报文格式与校验(messages.py)、常量(constants.py)
client/     身份(identity)/握手(handshake)/会话与重放(session)
            /消息收发(messaging)/传输(transport)/命令行(cli)
server/     注册(registry)/路由(relay)/持久化(storage)/入口(app)
web/        本地桥接(bridge.py)、纯 UI 网页(index.html)、账号库(db.py)
tests/      68 个单元与集成测试
report/     本报告与图示`));
  children.push(table(
    ["模块", "职责", "对应要求"],
    [
      ["crypto/primitives.py", "仅调用 vetted 库,封装签名/ECDH/HKDF/AEAD", "密码学正确性"],
      ["client/handshake.py", "临时密钥 + 身份签名握手,验签失败即拒", "SR3、防 A2 MitM、B1"],
      ["client/messaging.py", "AEAD 加解密,AD 绑定路由与计数器", "SR1、SR2"],
      ["client/session.py", "计数器 + 滑动窗口", "SR4"],
      ["crypto/fingerprint.py", "公钥安全号(带外比对)", "B2"],
      ["server/*", "全程只接触密文与路由元数据", "验证 A3"],
    ],
    [2400, 4200, 2426],
  ));

  // ====================================================================
  children.push(H1("6  Web 前端(方案 B:本地桥接)"));
  children.push(P("为提供图形界面同时不破坏 E2EE,网页采用「本地桥接」架构:浏览器只是瘦 UI、不持任何密钥;真正的端点是用户本机的桥接进程,它复用与 CLI 完全相同的 Python 加密代码完成握手与加解密,再经中继服务器与对端通信。"));
  (await image("web_architecture.png", "图 5  Web 前端架构(方案 B)")).forEach(p => children.push(p));
  children.push(P("为什么 E2EE 不受影响:端点 = 用户本机的桥接进程,明文仅存于「浏览器 + 本地桥接」,二者同机、属同一信任边界;中继服务器始终只见密文;浏览器↔桥接走 localhost 回环,属端点设备内部通信(类比桌面应用的 UI 与内核分离)。"));
  children.push(H2("6.1  账号认证与密码存储"));
  children.push(P("注册/登录采用用户名 + 密码,账号信息存入 MySQL。密码绝不以明文或可逆加密存储,而是用 scrypt(内存难解 KDF)加每用户 16 字节随机盐进行单向哈希,仅保存 (盐, 哈希);登录时重算并以常数时间比较:"));
  children.push(...codeBlock(
`_SCRYPT = dict(n=16384, r=8, p=1, dklen=32)

def _hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)

# 注册:salt = os.urandom(16); 存 (username, salt, scrypt(password, salt))
# 登录:hmac.compare_digest(_hash_password(输入, 存盐), 存哈希)   # 常数时间`));
  children.push(P("说明:对口令而言,正确做法是单向哈希而非可逆加密——即使数据库泄露也无法还原密码。该账号认证属客户端-服务器认证(可从简),与 E2EE 身份密钥相互独立;消息的端到端加密不依赖它。实测已验证两账号密码在库中均为 32 字节 scrypt 哈希且明文不存在,登录校验对错误密码返回拒绝。"));

  // ====================================================================
  children.push(H1("7  逐攻击者防御论证"));
  children.push(table(
    ["对手", "攻击手段", "防御机制", "满足", "残余局限"],
    [
      ["A1 被动", "监听密文", "ChaCha20-Poly1305 加密", "SR1", "泄漏长度/收发方/时序(显式允许)"],
      ["A2 主动", "篡改密文", "Poly1305 认证标签", "SR2", "—"],
      ["A2 主动", "伪造/注入", "无会话密钥无法生成有效标签", "SR3", "—"],
      ["A2 主动", "中间人(握手)", "身份私钥签名握手 + 验签", "SR3", "依赖公钥分发可信"],
      ["A2 主动", "重放", "计数器 + 滑动窗口 + AD 绑定", "SR4", "—"],
      ["A3 服务器", "偷窥内容", "端到端加密,服务器无密钥", "SR1", "可见路由元数据"],
    ],
    [1300, 1700, 2800, 900, 2326],
  ));
  children.push(H2("7.1  逐条论证"));
  children.push(P("A1(被动):消息体始终以 AEAD 密文形式出现在链路上;被动攻击者无会话密钥,无法恢复任何明文信息。→ SR1。"));
  children.push(P("A2(主动)— 篡改:任何对密文位的改动都会使 Poly1305 标签校验失败,接收方拒绝。→ SR2。"));
  children.push(P("A2 — 伪造/注入:标签由会话密钥保护;攻击者无密钥则无法构造能通过校验的帧。→ SR3。"));
  children.push(P("A2 — 中间人:握手材料由长期身份私钥签名,签名同时覆盖双方身份公钥。攻击者无身份私钥无法伪造合法握手;即便它替换响应方临时公钥,发起方验签也会失败(对应测试 test_initiator_rejects_swapped_ephemeral_key)。→ SR3。"));
  children.push(P("A2 — 重放:每条消息携带单调计数器,计数器又被绑入 AD;接收方以滑动窗口拒绝重复或越窗的计数器。→ SR4。"));
  children.push(P("A3(服务器):服务器只转发不解密(测试 test_data_forwarded_to_recipient_unchanged 证明密文原样转发);它既无会话密钥也无临时私钥,无法解密任何消息体。→ SR1。"));
  children.push(H2("7.2  加分项"));
  children.push(P("B1 前向保密(对抗 A4):每次会话都生成全新临时 X25519 密钥对,会话结束即销毁;会话密钥与长期身份密钥无关。因此即便日后窃取长期私钥,也无法重算过去会话的共享秘密,历史密文仍不可解(测试 test_fresh_sessions_have_independent_keys)。"));
  children.push(P("B2 恶意服务器抵抗(对抗 A5):应用消息由端到端 AEAD 保护,恶意服务器篡改/注入密文会被标签校验拒绝(SR2 不依赖服务器诚实);针对其分发假公钥实施的中间人,系统提供安全号(对双方身份公钥排序后哈希得到与顺序无关的可读数字串),双方带外比对一致即可确认无中间人。局限:安全号需用户手动比对,且未实现持久化 TOFU 信任库,故首次会话在比对前无法自动检测换钥——属部分实现。"));

  // ====================================================================
  children.push(H1("8  密码学正确性"));
  children.push(bullet("全部原语来自 vetted 库(cryptography),未自实现任何原语。"));
  children.push(bullet("密钥与一切随机量均来自库 CSPRNG(os.urandom)。"));
  children.push(bullet("nonce 由方向内单调计数器派生,且收发两方向使用不同密钥,确保 (key, nonce) 对永不重复。"));
  children.push(bullet("X25519 原始共享秘密一律经 HKDF 派生,info 标签绑定协议用途与方向。"));
  children.push(bullet("网络上不出现任何私钥/会话密钥;身份私钥仅存本地,口令仅以 scrypt 哈希存储。"));

  // ====================================================================
  children.push(H1("9  测试与验证"));
  children.push(P("项目附带 68 个自动化测试,全部通过,其中包含一个启动真实服务器 + 两个真实 WebSocket 客户端的全栈集成测试;网页端则通过浏览器实测验证了注册(写入哈希密码)、密码登录、握手与双向加密收发。"));
  children.push(table(
    ["测试文件", "项数", "覆盖"],
    [
      ["test_primitives.py", "16", "原语正确性、密文拒绝、序列化、安全号"],
      ["test_messages.py", "13", "报文往返、AD 防歧义、畸形帧拒绝"],
      ["test_handshake.py", "9", "密钥一致、伪造/换钥拒绝、前向保密"],
      ["test_replay.py", "9", "计数器单调、窗口边界、重放拒绝"],
      ["test_messaging.py", "12", "端到端往返、篡改/伪造/重放拒绝"],
      ["test_server.py", "8", "注册/查询/路由、密文原样转发、换钥拒绝"],
      ["test_integration.py", "1", "真实 WebSocket 全栈双客户端流程"],
      ["合计", "68", "全部通过"],
    ],
    [2600, 1200, 5226],
  ));

  // ====================================================================
  children.push(H1("10  局限与诚实声明"));
  children.push(bullet("身份私钥在磁盘上未加密存储(基础模型假定端点不被攻陷);生产系统应以口令派生密钥加封。"));
  children.push(bullet("不防护流量分析(消息大小/时序/收发方对服务器可见)。"));
  children.push(bullet("客户端-服务器认证刻意从简;B2 的假公钥检测依赖用户带外比对,非全自动。"));
  children.push(bullet("不应过度声称已实现的系统所能防御的范围。"));

  // ====================================================================
  children.push(H1("11  运行说明"));
  children.push(P("命令行演示:"));
  children.push(...codeBlock(
`python -m server.app                 # 启动中继服务器(端口 8765)
python -m client.cli chat --user alice
python -m client.cli chat --user bob
# 在 alice 端输入 /chat bob 完成握手后即可发送消息`));
  children.push(P("网页演示(需本机 MySQL):"));
  children.push(...codeBlock(
`# PowerShell 设置数据库凭据
$env:MYSQL_USER="root"; $env:MYSQL_PASSWORD="<your-password>"

python -m server.app                 # 中继服务器
python -m web.bridge                 # 桥接 + 网页(自动建库建表)
# 浏览器打开 http://127.0.0.1:8000 两个标签页,注册两个带密码的账号,
# 输入对方用户名发起加密会话后即可收发消息;可点「安全号校验」核对(B2)`));
  children.push(P("测试:python -m pytest tests/ -q  → 全部 68 项通过。"));

  // ---------- document ----------
  const doc = new Document({
    creator: "COMP5355 Group",
    title: "端到端加密一对一消息系统 技术报告",
    styles: {
      default: { document: { run: { font: FONT, size: 21 } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 32, bold: true, font: FONT, color: "1F2328" },
          paragraph: { spacing: { before: 320, after: 160 }, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 26, bold: true, font: FONT, color: "1F2328" },
          paragraph: { spacing: { before: 220, after: 120 }, outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 23, bold: true, font: FONT, color: "1F2328" },
          paragraph: { spacing: { before: 160, after: 100 }, outlineLevel: 2 } },
      ],
    },
    numbering: {
      config: [
        { reference: "bullets", levels: [
          { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 460, hanging: 260 } } } },
          { level: 1, format: LevelFormat.BULLET, text: "◦", alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 900, hanging: 260 } } } },
        ] },
      ],
    },
    sections: [{
      properties: {
        page: {
          size: { width: 11906, height: 16838 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "第 ", size: 18, color: "656D76" }),
            new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "656D76" }),
            new TextRun({ text: " 页", size: 18, color: "656D76" })],
        })] }),
      },
      children,
    }],
  });

  const buf = await Packer.toBuffer(doc);
  const out = path.join(__dirname, "COMP5355_E2EE_技术报告_中文.docx");
  fs.writeFileSync(out, buf);
  console.log("written:", out, buf.length, "bytes");
})();
