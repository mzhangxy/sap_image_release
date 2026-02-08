const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const { Buffer } = require('buffer');
const { WebSocket, createWebSocketStream } = require('ws');

// 环境变量配置
const UUID = process.env.UUID || 'f54ffa9f-0fa6-4a99-9ee6-6c21e7bc1d53';
const DOMAIN = process.env.DOMAIN || 'your-domain.com';    // 填写项目域名或已反代的域名
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      // 是否开启自动访问保活
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // WebSocket 路径
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 订阅路径
const NAME = process.env.NAME || '';                       // 节点名称
const PORT = process.env.PORT || 3000;                     // 服务端口

let CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1']; 
const BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
     'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

// 将 UUID 转换为 Buffer 以便 VLESS 校验
const UUID_BUFFER = Buffer.from(UUID.replace(/-/g, ''), 'hex');

// 屏蔽测速域名
function isBlockedDomain(host) {
    if (!host) return false;
    const hostLower = host.toLowerCase();
    return BLOCKED_DOMAINS.some(blocked => {
        return hostLower === blocked || hostLower.endsWith('.' + blocked);
    });
}

// 获取当前网络配置 (IP/ISP)
const GetConfig = async () => {    
    try {
        const res = await axios.get('https://speed.cloudflare.com/meta');
        const data = res.data;
        ISP = `${data.country}-${data.asOrganization}`.replace(/ /g, '_');
    } catch (e) {
        ISP = 'Unknown';
    }

    if (!DOMAIN || DOMAIN === 'your-domain.com') {
        try {
            const res = await axios.get('https://api.ip.sb/ip', { timeout: 8000 });
            const ip = res.data.trim();
            CurrentDomain = ip, Tls = 'none', CurrentPort = PORT;
        } catch (e) {
            console.error('Failed to get IP', e.message);
            CurrentDomain = 'your-domain.com', Tls = 'tls', CurrentPort = 443;
        }
    } else {
        CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443;
    }
}

const httpServer = http.createServer((req, res) => {
    if (req.url === '/') {
        const filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, 'utf8', (err, content) => {
            if (err) {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end('Hello world!');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(content);
        });
        return;
    } else if (req.url === `/${SUB_PATH}`) {
        GetConfig().then(() => { 
            const namePart = NAME ? `${NAME}-${ISP}` : ISP;
            
            // --- 生成 SS 链接 ---
            const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
            const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
            const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}-SS`;
            
            // --- 生成 VLESS 链接 ---
            // 格式: vless://uuid@host:port?encryption=none&security=tls&sni=host&type=ws&host=host&path=path#name
            const vlessSecurity = Tls === 'tls' ? 'tls' : 'none';
            const vlessURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${vlessSecurity}&sni=${CurrentDomain}&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}-VLESS`;

            const content = `${ssURL}\n${vlessURL}`;
            const base64Content = Buffer.from(content).toString('base64');
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(base64Content + '\n');
        });
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found\n');
    }
});

// DNS 解析工具
function resolveHost(host) {
    return new Promise((resolve, reject) => {
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
            resolve(host);
            return;
        }
        let attempts = 0;
        function tryNextDNS() {
            if (attempts >= DNS_SERVERS.length) {
                reject(new Error(`Failed to resolve ${host} with all DNS servers`));
                return;
            }
            const dnsServer = DNS_SERVERS[attempts];
            attempts++;
            const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
            axios.get(dnsQuery, {
                timeout: 5000,
                headers: { 'Accept': 'application/dns-json' }
            })
            .then(response => {
                const data = response.data;
                if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
                    const ip = data.Answer.find(record => record.type === 1);
                    if (ip) { resolve(ip.data); return; }
                }
                tryNextDNS();
            })
            .catch(error => { tryNextDNS(); });
        }
        tryNextDNS();
    });
}

// 通用连接器：建立到目标服务器的 TCP 连接并进行管道转发
function connectAndForward(host, port, ws, duplex, head) {
     resolveHost(host)
        .then(resolvedIP => {
            const client = net.connect({ host: resolvedIP, port }, function () {
                // 连接成功，将头部数据（如果还有剩余）写入
                this.write(head);
                // 建立双向管道: WS Stream <--> TCP Client
                duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
            });
            client.on('error', (err) => { 
                // console.error('TCP Connect Error:', err.message);
                // 连接失败，销毁流
                if (duplex) duplex.destroy();
            });
        })
        .catch(error => {
            // DNS 失败尝试直连
             const client = net.connect({ host, port }, function () {
                this.write(head);
                duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
            });
            client.on('error', () => { if (duplex) duplex.destroy(); });
        });
}

// --- VLESS 协议处理逻辑 ---
function handleVlessConnection(ws, msg) {
    try {
        let offset = 0;
        // 1. 验证版本号 (1 byte)
        const version = msg[offset++];
        if (version !== 0) return false;

        // 2. 验证 UUID (16 bytes)
        const uuidFromClient = msg.slice(offset, offset + 16);
        offset += 16;
        if (!uuidFromClient.equals(UUID_BUFFER)) return false;

        // 3. 跳过附加信息 (Addenda)
        const addendaLen = msg[offset++];
        offset += addendaLen;

        // 4. 解析命令 (1 byte): 1=TCP, 2=UDP
        const command = msg[offset++];
        // 目前仅支持 TCP (0x01)，UDP (0x02) 暂不处理或视作 TCP 尝试
        const isUDP = command === 2;

        // 5. 解析端口 (2 bytes Big-Endian)
        const port = msg.readUInt16BE(offset);
        offset += 2;

        // 6. 解析地址类型和地址
        const atyp = msg[offset++];
        let host;
        if (atyp === 1) { // IPv4
            host = msg.slice(offset, offset + 4).join('.');
            offset += 4;
        } else if (atyp === 2) { // Domain
            const domainLen = msg[offset++];
            host = msg.slice(offset, offset + domainLen).toString();
            offset += domainLen;
        } else if (atyp === 3) { // IPv6
            host = msg.slice(offset, offset + 16).reduce((s, b, i, a) =>
                (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
                .map(b => b.readUInt16BE(0).toString(16)).join(':');
            offset += 16;
        } else {
            return false; // 不支持的地址类型
        }

        if (isBlockedDomain(host)) { ws.close(); return false; }

        // VLESS 需要给客户端回送一个响应头: [Version 0x00] [Addenda Length 0x00]
        // 表示握手成功
        const responseHeader = Buffer.from([0, 0]);
        ws.send(responseHeader);

        // 获取剩余的数据（Payload）
        const payload = msg.slice(offset);

        // 建立流
        const duplex = createWebSocketStream(ws);
        
        // 发起连接
        connectAndForward(host, port, ws, duplex, payload);

        return true;
    } catch (e) {
        console.error('VLESS Error:', e);
        return false;
    }
}

// --- SS 协议处理逻辑 ---
function handleSsConnection(ws, msg) {
    try {
        let offset = 0;
        // SS 头部解析: [ATYP] [ADDR] [PORT]
        const atyp = msg[offset++];

        let host;
        if (atyp === 0x01) { // IPv4
            host = msg.slice(offset, offset + 4).join('.');
            offset += 4;
        } else if (atyp === 0x03) { // Domain
            const hostLen = msg[offset++];
            host = msg.slice(offset, offset + hostLen).toString();
            offset += hostLen;
        } else if (atyp === 0x04) { // IPv6
            host = msg.slice(offset, offset + 16).reduce((s, b, i, a) =>
                (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
                .map(b => b.readUInt16BE(0).toString(16)).join(':');
            offset += 16;
        } else {
            return false;
        }

        const port = msg.readUInt16BE(offset);
        offset += 2;
        
        if (isBlockedDomain(host)) {ws.close(); return false;}
        
        const payload = msg.slice(offset);
        const duplex = createWebSocketStream(ws);

        connectAndForward(host, port, ws, duplex, payload);

        return true;
    } catch (error) {
        return false;
    }
}

const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
    const url = req.url || '';
    const expectedPath = `/${WSPATH}`;
    if (!url.startsWith(expectedPath)) {
        ws.close();
        return;
    }
    
    ws.once('message', msg => {
        // 协议分流
        if (msg.length > 0) {
            const firstByte = msg[0];
            
            // 如果第一个字节是 0，尝试作为 VLESS 处理
            if (firstByte === 0x00) {
                if (handleVlessConnection(ws, msg)) return;
            } 
            // 如果第一个字节是 1, 3, 4，尝试作为 Shadowsocks 处理
            else if (firstByte === 0x01 || firstByte === 0x03 || firstByte === 0x04) {
                if (handleSsConnection(ws, msg)) return;
            }
        }
        
        // 无法识别的协议，关闭连接
        ws.close();
    }).on('error', () => { });
});

async function addAccessTask() {
    if (!AUTO_ACCESS) return;

    if (!DOMAIN) {
        return;
    }
    const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
    try {
        const res = await axios.post("https://oooo.serv00.net/add-url", {
            url: fullURL
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log('Automatic Access Task added successfully');
    } catch (error) {
        // console.error('Error adding Task:', error.message);
    }
}

httpServer.listen(PORT, async () => {
    addAccessTask();
    console.log(`Server is running on port ${PORT} (Dual Protocol: SS + VLESS)`);
});
