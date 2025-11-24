const fs = require('fs').promises;
const path = require('path');
const Handlebars = require('handlebars');
const NodeCache = require('node-cache');
const yaml = require('js-yaml');

// --- Template System ---
class TemplateSystem {
  constructor() {
    this.cache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });
    this.metadata = null;
    this.templatesDir = path.join(__dirname, 'templates');
  }

  async init() {
    try {
      // Load metadata
      const metadataPath = path.join(this.templatesDir, 'metadata.json');
      const metadataContent = await fs.readFile(metadataPath, 'utf8');
      this.metadata = JSON.parse(metadataContent);
      
      // Register custom helpers
      this.registerHelpers();
      
      console.log('✅ Template system initialized');
    } catch (error) {
      console.error('❌ Failed to initialize template system:', error);
      throw error;
    }
  }

  registerHelpers() {
    Handlebars.registerHelper('eq', (a, b) => a === b);
    Handlebars.registerHelper('gt', (a, b) => a > b);
    Handlebars.registerHelper('json', (obj) => JSON.stringify(obj));
    Handlebars.registerHelper('unless', (conditional, options) => {
      if (!conditional) {
        return options.fn(this);
      }
    });
  }

  async loadTemplate(format, level) {
    const cacheKey = `${format}:${level}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    const extensionMap = {
      clash: 'yaml.hbs',
      singbox: 'json.hbs',
      surge: 'ini.hbs',
      quantumult: 'ini.hbs',
    };
    const extension = extensionMap[format] || 'hbs';
    const templateName = `${level}.${extension}`;

    try {
      const templatePath = path.join(this.templatesDir, format, templateName);
      const source = await fs.readFile(templatePath, 'utf8');
      const template = Handlebars.compile(source);
      
      this.cache.set(cacheKey, template);
      return template;
    } catch (error) {
      console.error(`❌ Failed to load template ${format}:${level} (tried ${templateName}):`, error.message);

      // Fallback to basic level only if the requested level was not 'basic'
      if (level !== 'basic') {
        console.log(`🔄 Falling back to basic template for ${format}`);
        return this.loadTemplate(format, 'basic');
      }

      // If even 'basic' fails, throw the original error
      throw new Error(`Template for ${format} at level ${level} could not be loaded. Original error: ${error.message}`);
    }
  }

  async generateConfig(format, level, data) {
    const template = await this.loadTemplate(format, level);
    return template(data);
  }

  getTemplateInfo(format) {
    return this.metadata?.[format] || null;
  }

  getAvailableLevels(format) {
    return Object.keys(this.metadata?.[format] || {});
  }
}

// Initialize template system
const templateSystem = new TemplateSystem();

// --- Fungsi Parsing ---
function parseVLESS(link) {
  if (!link.startsWith('vless://')) {
    throw new Error('Bukan link VLESS');
  }

  const clean = link.replace('vless://', '');
  const [userinfo, rest] = clean.split('@');
  const [uuid] = userinfo.split(':');

  const [hostport, paramString] = rest.split('?');
  const [host, port] = hostport.split(':');

  const params = {};
  let fragmentName = '';

  if (paramString) {
    const paramParts = paramString.split('#');
    const queryParams = paramParts[0];
    fragmentName = paramParts[1] ? paramParts[1] : '';

    if (queryParams) {
      queryParams.split('&').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) {
          params[decodeURIComponent(key)] = decodeURIComponent(value || '');
        }
      });
    }
  }

  let name = 'VLESS Server';
  if (fragmentName) {
    try {
      name = decodeURIComponent(fragmentName);
    } catch (e) {
      console.warn("Gagal decode fragment untuk VLESS link:", e.message);
      name = fragmentName;
    }
  }

  return {
    type: 'vless',
    uuid,
    host,
    port: parseInt(port, 10),
    security: params.security || 'none',
    flow: params.flow || '',
    network: params.type || 'tcp',
    path: params.path || (params.type === 'ws' ? '/' : ''),
    host_header: params.host || '',
    sni: params.sni || params.host || host,
    fp: params.fp || '',
    pbk: params.pbk || '',
    sid: params.sid || '',
    spx: params.spx || '',
    alpn: params.alpn || '',
    allowInsecure: params.allowInsecure === '1' || params.allowInsecure === 'true' || false,
    name: name
  };
}

function parseVMess(link) {
  if (!link.startsWith('vmess://')) {
    throw new Error('Bukan link VMess');
  }

  const base64 = link.replace('vmess://', '');
  let jsonStr;
  try {
    jsonStr = Buffer.from(base64, 'base64').toString('utf8');
    const obj = JSON.parse(jsonStr);
    
    let name = 'VMess Server';
    if (obj.ps) {
      try {
        name = decodeURIComponent(obj.ps);
      } catch (e) {
        console.warn("Gagal decode 'ps' untuk VMess link:", e.message);
        name = obj.ps;
      }
    }
    
    return {
      type: 'vmess',
      uuid: obj.id,
      host: obj.add,
      port: parseInt(obj.port, 10),
      alterId: parseInt(obj.aid, 10) || 0,
      security: obj.sc || obj.cipher || 'auto',
      network: obj.net || 'tcp',
      type: obj.type || 'none',
      path: obj.path || (obj.net === 'ws' ? '/' : ''),
      host_header: obj.host || obj.add,
      sni: obj.sni || obj.host || obj.add,
      tls: obj.tls === 'tls',
      alpn: obj.alpn || '',
      fp: obj.fp || '',
      name: name
    };
  } catch (e) {
    throw new Error('Invalid VMess base64 JSON');
  }
}

function parseTrojan(link) {
  if (!link.startsWith('trojan://')) {
    throw new Error('Bukan link Trojan');
  }

  const cleanLink = link.substring('trojan://'.length);
  const paramStartIndex = cleanLink.indexOf('?');
  const fragmentStartIndex = cleanLink.indexOf('#');

  let userinfo_and_serverinfo = '';
  let paramString = '';
  let fragment = '';

  if (paramStartIndex === -1 && fragmentStartIndex === -1) {
    userinfo_and_serverinfo = cleanLink;
  } else if (paramStartIndex !== -1 && fragmentStartIndex === -1) {
    userinfo_and_serverinfo = cleanLink.substring(0, paramStartIndex);
    paramString = cleanLink.substring(paramStartIndex + 1);
  } else if (paramStartIndex === -1 && fragmentStartIndex !== -1) {
    userinfo_and_serverinfo = cleanLink.substring(0, fragmentStartIndex);
    fragment = cleanLink.substring(fragmentStartIndex + 1);
  } else {
    userinfo_and_serverinfo = cleanLink.substring(0, paramStartIndex);
    if (fragmentStartIndex > paramStartIndex) {
      paramString = cleanLink.substring(paramStartIndex + 1, fragmentStartIndex);
      fragment = cleanLink.substring(fragmentStartIndex + 1);
    } else {
      paramString = cleanLink.substring(paramStartIndex + 1);
    }
  }

  const [userinfo, serverinfo] = userinfo_and_serverinfo.split('@');
  if (!userinfo || !serverinfo) {
    throw new Error('Invalid Trojan link format: Missing userinfo or serverinfo');
  }

  const [host, portStr] = serverinfo.split(':');
  const port = parseInt(portStr, 10);
  if (isNaN(port)) {
    throw new Error('Invalid Trojan link format: Invalid port');
  }

  const params = {};
  if (paramString) {
    paramString.split('&').forEach(pair => {
      if (pair) {
        const [key, value = ''] = pair.split('=');
        if (key) {
          params[decodeURIComponent(key)] = decodeURIComponent(value);
        }
      }
    });
  }

  let name = 'Trojan Server';
  if (fragment) {
    try {
      name = decodeURIComponent(fragment);
    } catch (e) {
      console.warn("Gagal mendecode fragment/tag untuk Trojan link:", e.message);
      name = fragment || name;
    }
  }

  return {
    type: 'trojan',
    password: decodeURIComponent(userinfo),
    host,
    port: port,
    security: 'tls',
    network: params.type || 'tcp',
    path: params.path || (params.type === 'ws' ? '/' : ''),
    host_header: params.host || host,
    sni: params.sni || params.host || host,
    alpn: params.alpn || '',
    fp: params.fp || '',
    allowInsecure: params.allowInsecure === '1' || params.allowInsecure === 'true' || false,
    name: name,
  };
}

function parseSS(link) {
  if (!link.startsWith('ss://')) {
    throw new Error('Not a Shadowsocks link');
  }

  const fragmentIndex = link.indexOf('#');
  const fragment = fragmentIndex !== -1 ? link.substring(fragmentIndex + 1) : '';
  const clean = link.substring(0, fragmentIndex !== -1 ? fragmentIndex : link.length).replace('ss://', '');

  const [userinfo, hostport] = clean.split('@');
  const [host, portWithParams] = hostport.split(':');
  const [portPart, ...paramParts] = portWithParams.split('?');
  const port = parseInt(portPart, 10);

  let method = 'chacha20-ietf-poly1305';
  let password = '';
  try {
    const decoded = Buffer.from(userinfo, 'base64').toString('utf8');
    const [m, p] = decoded.split(':', 2);
    method = m;
    password = p;
  } catch (e) {
    throw new Error('Invalid Shadowsocks base64 encoding');
  }

  let plugin = '';
  let plugin_opts = '';
  let obfs = '';
  let obfsHost = '';

  if (paramParts.length > 0) {
    const params = new URLSearchParams(paramParts.join('?'));
    const rawPlugin = params.get('plugin') || '';
    if (rawPlugin) {
      const parts = rawPlugin.split(';');
      plugin = parts[0];
      plugin_opts = parts.slice(1).join(';');
    }
    obfs = params.get('obfs') || '';
    obfsHost = params.get('obfs-host') || '';
  }

  let name = 'SS Server';
  if (fragment) {
    try {
      name = decodeURIComponent(fragment);
    } catch (e) {
      console.warn("Gagal decode fragment untuk SS link:", e.message);
      name = fragment;
    }
  }

  return {
    type: 'ss',
    method,
    password,
    host,
    port,
    plugin,
    plugin_opts,
    obfs,
    obfsHost,
    name: name
  };
}

function parseAnyLink(link) {
  if (!link || typeof link !== 'string') {
    throw new Error('Link must be a non-empty string');
  }
  
  if (link.length > 2000) {
    throw new Error('Link is too long');
  }
  
  if (link.startsWith('vless://')) return parseVLESS(link);
  if (link.startsWith('vmess://')) return parseVMess(link);
  if (link.startsWith('trojan://')) return parseTrojan(link);
  if (link.startsWith('ss://')) return parseSS(link);
  
  throw new Error('Unsupported protocol. Supported: vless, vmess, trojan, ss');
}

// --- Fungsi Konversi ---
function toClash(config) {
  const clashConfig = {
    name: config.name,
    type: config.type,
    server: config.host,
    port: config.port,
    udp: true,
    'skip-cert-verify': !!config.allowInsecure,
  };

  switch (config.type) {
    case 'vless':
      clashConfig.uuid = config.uuid;
      clashConfig.tls = config.security === 'tls' || config.security === 'reality';
      if (clashConfig.tls) {
        if (config.sni) clashConfig.servername = config.sni;
        if (config.alpn) clashConfig.alpn = config.alpn.split(',').map(a => a.trim());
        if (config.fp) clashConfig.fingerprint = config.fp;

        if (config.security === 'reality') {
          clashConfig['client-fingerprint'] = config.fp;
          if (config.pbk) clashConfig['public-key'] = config.pbk;
          if (config.sid) clashConfig['short-id'] = config.sid;
          if (config.spx) clashConfig['spider-x'] = config.spx;
        } else if (config.security === 'tls') {
          if (config.flow) clashConfig.flow = config.flow;
        }
      }
      if (config.network === 'ws') {
        clashConfig.network = 'ws';
        clashConfig['ws-path'] = config.path || '/';
        if (config.host_header) {
          clashConfig['ws-headers'] = { host: config.host_header };
        }
      }
      break;

    case 'vmess':
      clashConfig.uuid = config.uuid;
      clashConfig.alterId = config.alterId;
      clashConfig.cipher = config.security;
      clashConfig.tls = !!config.tls;
      if (clashConfig.tls) {
        if (config.sni) clashConfig.servername = config.sni;
        if (config.alpn) clashConfig.alpn = config.alpn.split(',').map(a => a.trim());
        if (config.fp) clashConfig.fingerprint = config.fp;
      }
      if (config.network === 'ws') {
        clashConfig.network = 'ws';
        clashConfig['ws-path'] = config.path || '/';
        if (config.host_header) {
          clashConfig['ws-headers'] = { host: config.host_header };
        }
      }
      break;

    case 'trojan':
      clashConfig.password = config.password;
      clashConfig.tls = true;
      if (config.sni) clashConfig.sni = config.sni;
      if (config.alpn) clashConfig.alpn = config.alpn.split(',').map(a => a.trim());
      if (config.fp) clashConfig.fingerprint = config.fp;
      if (config.network === 'ws') {
        clashConfig.network = 'ws';
        clashConfig['ws-path'] = config.path || '/';
        if (config.host_header) {
          clashConfig['ws-headers'] = { host: config.host_header };
        }
      }
      break;

    case 'ss':
      clashConfig.cipher = config.method;
      clashConfig.password = config.password;
      if (config.plugin) {
        clashConfig.plugin = config.plugin;

        const opts = {};
        if (config.plugin_opts) {
            config.plugin_opts.split(';').forEach(part => {
                if (part) {
                    const [key, ...valParts] = part.split('=');
                    const value = valParts.join('=');
                    if (key === 'tls') {
                        opts[key] = true;
                    } else if (value) {
                        opts[key] = value;
                    }
                }
            });
        }

        if (Object.keys(opts).length > 0) {
            clashConfig['plugin-opts'] = opts;
        } else if (config.obfs) {
            // Fallback for simple-obfs
            clashConfig['plugin-opts'] = {
                mode: config.obfs,
                host: config.obfsHost
            };
        }
      }
      break;

    default:
      throw new Error(`Tidak dapat mengkonversi protokol '${config.type}' ke format Clash.`);
  }

  // Use yaml.dump to convert the object to a YAML string.
  // The output from dump includes a trailing newline, which is what we want.
  // We pass an array with the single config object to ensure it starts with '- '.
  return yaml.dump([clashConfig], { indent: 2 }).trim();
}

function toSurge(config) {
  switch (config.type) {
    case 'vless':
      let vlessOpts = `skip-cert-verify=${!!config.allowInsecure}`;
      if (config.security === 'tls') {
        vlessOpts += `, tls=true, sni=${config.sni}`;
        if(config.alpn) vlessOpts += `, alpn=${config.alpn}`;
        if(config.fp) vlessOpts += `, server-cert-fingerprint-sha256=${config.fp}`;
      } else if (config.security === 'reality') {
        vlessOpts += `, tls=true, sni=${config.sni}`;
      }
      if (config.flow) vlessOpts += `, flow=${config.flow}`;
      if (config.network === 'ws') {
        vlessOpts += `, ws=true, ws-path=${config.path}`;
        if (config.host_header) vlessOpts += `, ws-headers=host:${config.host_header}`;
      }
      return `${config.name} = vless, ${config.host}, ${config.port}, username=${config.uuid}, ${vlessOpts}`;
      
    case 'vmess':
      let vmessOpts = `skip-cert-verify=${!!config.allowInsecure}`;
      if (config.tls) {
        vmessOpts += `, tls=true, sni=${config.sni}`;
        if(config.alpn) vmessOpts += `, alpn=${config.alpn}`;
        if(config.fp) vmessOpts += `, server-cert-fingerprint-sha256=${config.fp}`;
      }
      if (config.network === 'ws') {
        vmessOpts += `, ws=true, ws-path=${config.path}`;
        if (config.host_header) vmessOpts += `, ws-headers=host:${config.host_header}`;
      }
      return `${config.name} = vmess, ${config.host}, ${config.port}, username=${config.uuid}, ${vmessOpts}`;
      
    case 'trojan':
      let trojanOpts = `skip-cert-verify=${!!config.allowInsecure}`;
      trojanOpts += `, sni=${config.sni}`;
      if(config.alpn) trojanOpts += `, alpn=${config.alpn}`;
      if(config.fp) trojanOpts += `, server-cert-fingerprint-sha256=${config.fp}`;
      if (config.network === 'ws') {
        trojanOpts += `, ws=true, ws-path=${config.path}`;
        if (config.host_header) trojanOpts += `, ws-headers=host:${config.host_header}`;
      }
      return `${config.name} = trojan, ${config.host}, ${config.port}, password=${config.password}, ${trojanOpts}`;
      
    case 'ss':
      if (config.plugin) {
        return `${config.name} = custom, ${config.host}, ${config.port}, ${config.method}, ${config.password}, https://raw.githubusercontent.com/ConnersHua/SSEncrypt/master/SSEncrypt.module`;
      } else {
        return `${config.name} = ss, ${config.host}, ${config.port}, ${config.method}, ${config.password}`;
      }
      
    default:
      throw new Error(`Unsupported type for Surge: ${config.type}`);
  }
}

function toQuantumult(config) {
  switch (config.type) {
    case 'vless':
      let vlessParams = `skip-cert-verify=${!!config.allowInsecure}`;
      if (config.security === 'tls') {
        vlessParams += `, tls=true, sni=${config.sni}`;
        if(config.alpn) vlessParams += `, alpn=${config.alpn}`;
        if(config.fp) vlessParams += `, tls-cert-sha256=${config.fp}`;
      } else if (config.security === 'reality') {
        vlessParams += `, tls=true, sni=${config.sni}`;
      }
      if (config.flow) vlessParams += `, flow=${config.flow}`;
      if (config.network === 'ws') {
        vlessParams += `, ws=true, ws-path=${config.path}`;
        if (config.host_header) vlessParams += `, ws-header=host:${config.host_header}`;
      }
      return `vmess=${config.host}:${config.port}, method=none, password=${config.uuid}, ${vlessParams}, tag=${config.name}`;
      
    case 'vmess':
      let vmessParams = `skip-cert-verify=${!!config.allowInsecure}`;
      if (config.tls) {
        vmessParams += `, tls=${config.tls}, sni=${config.sni}`;
        if(config.alpn) vmessParams += `, alpn=${config.alpn}`;
        if(config.fp) vmessParams += `, tls-cert-sha256=${config.fp}`;
      }
      if (config.network === 'ws') {
        vmessParams += `, ws=true, ws-path=${config.path}`;
        if (config.host_header) vmessParams += `, ws-header=host:${config.host_header}`;
      }
      return `vmess=${config.host}:${config.port}, method=none, password=${config.uuid}, ${vmessParams}, tag=${config.name}`;
      
    case 'trojan':
      let trojanParams = `skip-cert-verify=${!!config.allowInsecure}`;
      trojanParams += `, over-tls=true, tls-host=${config.sni}`;
      if(config.alpn) trojanParams += `, alpn=${config.alpn}`;
      if(config.fp) trojanParams += `, tls-cert-sha256=${config.fp}`;
      if (config.network === 'ws') {
        trojanParams += `, ws=true, ws-path=${config.path}`;
        if (config.host_header) trojanParams += `, ws-header=host:${config.host_header}`;
      }
      return `trojan=${config.host}:${config.port}, password=${config.password}, ${trojanParams}, tag=${config.name}`;
      
    case 'ss':
      let ssParams = `encrypt-method=${config.method}, password=${config.password}`;
      if (config.obfs) ssParams += `, obfs=${config.obfs}, obfs-host=${config.obfsHost}`;
      return `shadowsocks=${config.host}:${config.port}, method=${config.method}, password=${config.password}, ${ssParams}, tag=${config.name}`;
      
    default:
      throw new Error(`Unsupported type for Quantumult: ${config.type}`);
  }
}

function toSingBox(config) {
  let base = {
      tag: config.name,
      type: config.type === 'ss' ? 'shadowsocks' : config.type,
      server: config.host,
      server_port: config.port
  };

  if (config.type === 'vless' || config.type === 'vmess') {
      base.uuid = config.uuid;
      if (config.type === 'vmess') base.alter_id = config.alterId;
      
      if (config.network === 'ws') {
          base.transport = {
              type: 'ws',
              path: config.path || '/',
              headers: config.host_header ? { host: config.host_header } : {}
          };
      }

      if (config.network === 'grpc') {
          base.transport = {
              type: 'grpc',
              service_name: config.serviceName || ''
          };
      }

      if (config.security === 'tls' || config.security === 'reality' || config.tls) {
          base.tls = {
              enabled: true,
              server_name: config.sni || config.host,
              insecure: !!config.allowInsecure
          };
          if (config.alpn) {
              base.tls.alpn = config.alpn.split(',').map(a => a.trim()).filter(a => a);
          }
          if (config.security === 'reality') {
              base.tls.utls = { enabled: true, fingerprint: config.fp || "chrome" };
              base.tls.reality = { enabled: true, public_key: config.pbk, short_id: config.sid };
              base.tls.flow = config.flow || "";
          } else if (config.security === 'tls') {
              base.tls.utls = { enabled: true, fingerprint: config.fp || "chrome" };
              if (config.flow) base.tls.flow = config.flow;
          }
      } else {
          base.tls = { enabled: false };
      }
      if (config.security === 'none' && !config.tls) {
          base.tls = { enabled: false };
      }

  } else if (config.type === 'trojan') {
      base.password = config.password;
      
      if (config.network === 'ws') {
          base.transport = {
              type: 'ws',
              path: config.path || '/',
              headers: config.host_header ? { host: config.host_header } : {}
          };
      }

      base.tls = {
          enabled: true,
          server_name: config.sni || config.host,
          insecure: !!config.allowInsecure,
          utls: { enabled: true, fingerprint: config.fp || "chrome" }
      };
      if (config.alpn) {
          base.tls.alpn = config.alpn.split(',').map(a => a.trim()).filter(a => a);
      }

  } else if (config.type === 'ss') {
      base.method = config.method;
      base.password = config.password;

      if (config.plugin) {
          base.plugin = config.plugin;
          if (config.plugin_opts) {
            base.plugin_opts = config.plugin_opts;
          }
      }
  }

  return JSON.stringify(base, null, 2);
}

// --- Helper Functions ---
async function extractLinks(rawInput) {
  console.log("--- DEBUG: Mulai proses ekstraksi link (Metode GET - Sederhana) ---");
  console.log("Panjang input 'link' dari user:", rawInput.length);

  if (!rawInput || typeof rawInput !== 'string') {
      console.log("DEBUG: Input tidak valid atau kosong.");
      throw new Error('Input link tidak valid.');
  }

  const potentialLinks = rawInput.split(',').map(l => l.trim()).filter(l => l.length > 0);
  const extractedLinks = [];

  for (let i = 0; i < potentialLinks.length; i++) {
      const link = potentialLinks[i];
      if (link.length > 30 && (link.includes('@') || link.includes('#'))) {
          console.log(`DEBUG: Link ${i+1} lolos validasi awal (GET).`);
          extractedLinks.push(link);
      } else {
          console.warn(`DEBUG: Link ${i+1} diabaikan karena tidak lulus validasi awal (GET). Panjang: ${link.length}`);
      }
  }

  console.log("DEBUG: Link yang berhasil diekstrak (GET):", extractedLinks.map(l => l.substring(0, 50) + (l.length > 50 ? "..." : "")));
  console.log("--- DEBUG: Akhir proses ekstraksi link (GET) ---");

  if (extractedLinks.length === 0) {
      throw new Error('Tidak ditemukan link VPN yang valid dalam input GET.');
  }

  return extractedLinks;
}

async function processLinks(links, startIndex = 0) {
  const results = [];
  
  for (let i = 0; i < links.length; i++) {
    const singleLink = links[i];
    
    try {
      const parsed = parseAnyLink(singleLink);
      const originalName = parsed.name || "Proxy Server";
      const configName = `${originalName}-${startIndex + i + 1} [vortexVpn]`;

      const config = {
        ...parsed,
        name: configName,
        network: parsed.network || 'tcp'
      };

      const formats = {
        clash: toClash(config),
        surge: toSurge(config),
        quantumult: toQuantumult(config),
        singbox: toSingBox(config)
      };
      
      results.push({ 
        original: config, 
        formats, 
        link: singleLink,
        tag: configName
      });
    } catch (convertError) {
      console.error(`Gagal konversi link (${singleLink.substring(0, 50)}...):`, convertError.message);
      results.push({ error: convertError.message, link: singleLink });
    }
  }
  
  return results;
}

// --- Generic Handler Functions ---
async function handleGenericConvertRequest(req, res, getLinks) {
  const format = req.params.format.toLowerCase();
  const level = req.query.level || req.body.level || 'standard';

  if (!['clash', 'surge', 'quantumult', 'singbox'].includes(format)) {
    return res.status(400).json({ 
      error: 'Format tidak didukung. Gunakan: clash, surge, quantumult, singbox' 
    });
  }

  try {
    const links = await getLinks(req);
    if (!links || (Array.isArray(links) && links.length === 0)) {
        return res.status(400).json({ error: 'Input link tidak valid atau kosong.' });
    }

    const results = await processLinks(links);
    const successfulResults = results.filter(r => !r.error);

    if (successfulResults.length > 0) {
      const config = await generateConfigByFormat(format, level, successfulResults);
      
      const mimeTypes = {
        clash: 'text/yaml',
        surge: 'text/plain',
        quantumult: 'text/plain',
        singbox: 'application/json'
      };

      res.set('Content-Type', mimeTypes[format]);
      res.set('X-Template-Level', level);
      res.set('X-Proxies-Processed', successfulResults.length.toString());
      res.send(config);
    } else {
      const errorMessages = results
        .filter(r => r.error)
        .map(r => `Link: ${r.link}\nError: ${r.error}`)
        .join('\n\n');
      
      res.status(400).send(`Semua link gagal dikonversi:\n\n${errorMessages}`);
    }
  } catch (error) {
    console.error(`Error in handleGenericConvertRequest for ${req.method}:`, error);
    res.status(500).json({ error: error.message });
  }
}

async function handleGenericRawRequest(req, res, getLinks) {
    const format = req.params.format.toLowerCase();

    if (!['clash', 'surge', 'quantumult', 'singbox'].includes(format)) {
        return res.status(400).json({
            error: 'Format tidak didukung. Gunakan: clash, surge, quantumult, singbox'
        });
    }

    try {
        const links = await getLinks(req);
        if (!links || (Array.isArray(links) && links.length === 0)) {
            return res.status(400).json({ error: 'Input link tidak valid atau kosong.' });
        }

        const results = await processLinks(links);
        const successfulResults = results.filter(r => !r.error);

        if (successfulResults.length > 0) {
            const structuredOutput = {
                tags: successfulResults.map(r => r.tag),
                [format === 'singbox' ? 'outbounds' : 'proxies']: successfulResults.map(r => {
                    if (format === 'singbox') {
                        return JSON.parse(r.formats.singbox);
                    } else {
                        return parseProxyConfig(r.formats[format]);
                    }
                })
            };

            res.set('Content-Type', 'application/json');
            res.set('X-Outbounds-Count', successfulResults.length.toString());
            res.json(structuredOutput);
        } else {
            const errorMessages = results
                .filter(r => r.error)
                .map(r => `Link: ${r.link}\nError: ${r.error}`)
                .join('\n\n');

            res.status(400).send(`Semua link gagal dikonversi:\n\n${errorMessages}`);
        }
    } catch (error) {
        console.error(`Error in handleGenericRawRequest for ${req.method}:`, error);
        res.status(500).json({ error: error.message });
    }
}

// --- Handler Functions ---
const getLinksFromQuery = async (req) => {
    const { link } = req.query;
    if (!link) return [];
    return await extractLinks(link);
};

const getLinksFromBody = async (req) => {
    const { links } = req.body;
    if (!links || !Array.isArray(links)) return [];
    return links;
};

const handleConvertRequest = (req, res) => handleGenericConvertRequest(req, res, getLinksFromQuery);
const handleConvertPostRequest = (req, res) => handleGenericConvertRequest(req, res, getLinksFromBody);
const handleRawRequest = (req, res) => handleGenericRawRequest(req, res, getLinksFromQuery);
const handleRawPostRequest = (req, res) => handleGenericRawRequest(req, res, getLinksFromBody);

function getTemplateInfo(req, res) {
  const format = req.params.format.toLowerCase();
  const info = templateSystem.getTemplateInfo(format);
  
  if (!info) {
    return res.status(404).json({ error: 'Format not found' });
  }
  
  res.json(info);
}

// --- Helper Functions for Config Generation ---
async function generateConfigByFormat(format, level, results) {
  const validProxies = results.filter(r => !r.error);
  
  switch (format) {
    case 'clash':
      return await generateClashConfig(validProxies, level);
    case 'surge':
      return await generateSurgeConfig(validProxies, level);
    case 'quantumult':
      return await generateQuantumultConfig(validProxies, level);
    case 'singbox':
      return await generateSingBoxConfig(validProxies, level);
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}

async function generateClashConfig(results, level) {
  const data = {
    proxies: results.map(r => r.formats.clash),
    proxyNames: results.map(r => r.original.name),
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  };
  
  return await templateSystem.generateConfig('clash', level, data);
}

async function generateSurgeConfig(results, level) {
  const data = {
    proxies: results.map(r => r.formats.surge),
    proxyNames: results.map(r => r.original.name),
    timestamp: new Date().toISOString()
  };
  
  return await templateSystem.generateConfig('surge', level, data);
}

async function generateQuantumultConfig(results, level) {
  const data = {
    proxies: results.map(r => r.formats.quantumult),
    proxyNames: results.map(r => r.original.name),
    timestamp: new Date().toISOString()
  };
  
  return await templateSystem.generateConfig('quantumult', level, data);
}

async function generateSingBoxConfig(results, level) {
  const outbounds = results.map(r => JSON.parse(r.formats.singbox));
  const proxyTags = results.map(r => r.tag);
  
  const data = {
    outbounds: outbounds,
    proxyNames: proxyTags,
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  };
  
  return await templateSystem.generateConfig('singbox', level, data);
}

function parseProxyConfig(configString) {
  const lines = configString.split('\n');
  const config = {};
  
  lines.forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      if (trimmed.startsWith('- ')) {
        const [key, ...valueParts] = trimmed.substring(2).split(':');
        const value = valueParts.join(':').trim();
        config[key.trim()] = value.replace(/"/g, '');
      } else {
        const [key, ...valueParts] = trimmed.split(':');
        if (valueParts.length > 0) {
          const value = valueParts.join(':').trim();
          config[key.trim()] = value.replace(/"/g, '');
        }
      }
    }
  });
  
  return config;
}

// --- Initialize template system on startup
(async () => {
  try {
    await templateSystem.init();
    console.log('✅ Template system ready');
  } catch (error) {
    console.error('❌ Failed to initialize template system:', error);
    process.exit(1);
  }
})();

// --- Exports ---
module.exports = {
  handleConvertRequest,
  handleConvertPostRequest,
  handleRawRequest,
  handleRawPostRequest,
  getTemplateInfo,
  parseTrojan,
};
