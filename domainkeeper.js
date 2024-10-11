// 在文件顶部添加版本信息后台密码（不可为空）
const VERSION = "1.8.1";

// 自定义标题
const CUSTOM_TITLE = "我的域名管理";

// 在这里设置你的多个 Cloudflare API Token
const CF_API_KEYS = [
  "", //user1
  "" //user2
];

// 对应的用户名数组
const USERNAMES = [
  "", // username1
  "" // username2
];

// 自建 WHOIS 代理服务地址
const WHOIS_PROXY_URL = "";

// 访问密码（可为空）
const ACCESS_PASSWORD = "";

// 后台密码（不可为空）
const ADMIN_PASSWORD = "lgd123456";

// KV 命名空间绑定名称
const KV_NAMESPACE = DOMAIN_INFO;

// 清理 KV 中的错误数据
async function cleanupKV() {
  const list = await KV_NAMESPACE.list();
  for (const key of list.keys) {
    const value = await KV_NAMESPACE.get(key.name);
    if (value) {
      const { data } = JSON.parse(value);
      if (data.whoisError) {
        await KV_NAMESPACE.delete(key.name);
      }
    }
  }
}

// footerHTML
const footerHTML = `
  <footer style="
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: #f8f9fa;
    color: #6c757d;
    text-align: center;
    padding: 10px 0;
    font-size: 14px;
  ">
    Powered by DomainKeeper v${VERSION} <span style="margin: 0 10px;">|</span> © 2024 NieGe. All rights reserved.
  </footer>
`;

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

async function handleRequest(request) {
  // 清理KV中的错误数据
  await cleanupKV();
  
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/manual-query") {
    return handleManualQuery(request);
  }

  if (path === "/") {
    return handleFrontend(request);
  } else if (path === "/admin") {
    return handleAdmin(request);
  } else if (path === "/api/update") {
    return handleApiUpdate(request);
  } else if (path === "/login") {
    return handleLogin(request);
  } else if (path === "/admin-login") {
    return handleAdminLogin(request);
  } else if (path.startsWith("/whois/")) {
    const domain = path.split("/")[2];
    return handleWhoisRequest(domain);
  } else {
    return new Response("Not Found", { status: 404 });
  }
}

async function handleManualQuery(request) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const data = await request.json();
  const { domain, apiKey } = data;

  try {
    const whoisInfo = await fetchWhoisInfo(domain, apiKey);
    await cacheWhoisInfo(domain, whoisInfo);
    return new Response(JSON.stringify(whoisInfo), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function cleanupKV() {
  const list = await KV_NAMESPACE.list();
  for (const key of list.keys) {
    const value = await KV_NAMESPACE.get(key.name);
    if (value) {
      const { data } = JSON.parse(value);
      if (data.whoisError) {
        await KV_NAMESPACE.delete(key.name);
      }
    }
  }
}

async function handleFrontend(request) {
  const cookie = request.headers.get("Cookie");
  if (ACCESS_PASSWORD && (!cookie || !cookie.includes(`access_token=${ACCESS_PASSWORD}`))) {
    return Response.redirect(`${new URL(request.url).origin}/login`, 302);
  }

  console.log("Fetching Cloudflare domains info...");
  const domains = await fetchCloudflareDomainsInfo();
  console.log("Cloudflare domains:", domains);

  console.log("Fetching domain info...");
  const domainsWithInfo = await fetchDomainInfo(domains);
  console.log("Domains with info:", domainsWithInfo);

  return new Response(generateHTML(domainsWithInfo, false), {
    headers: { 'Content-Type': 'text/html' },
  });
}

async function handleAdmin(request) {
  const cookie = request.headers.get("Cookie");
  if (!cookie || !cookie.includes(`admin_token=${ADMIN_PASSWORD}`)) {
    return Response.redirect(`${new URL(request.url).origin}/admin-login`, 302);
  }

  const domains = await fetchCloudflareDomainsInfo();
  const domainsWithInfo = await fetchDomainInfo(domains);
  return new Response(generateHTML(domainsWithInfo, true), {
    headers: { 'Content-Type': 'text/html' },
  });
}

async function handleLogin(request) {
  if (request.method === "POST") {
    const formData = await request.formData();
    const password = formData.get("password");
    
    console.log("Entered password:", password);
    console.log("Expected password:", ACCESS_PASSWORD);
    
    if (password === ACCESS_PASSWORD) {
      return new Response("Login successful", {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie": `access_token=${ACCESS_PASSWORD}; HttpOnly; Path=/; SameSite=Strict`
        }
      });
    } else {
      return new Response(generateLoginHTML("前台登录", "/login", "密码错误，请重试。"), {
        headers: { "Content-Type": "text/html" },
        status: 401
      });
    }
  }
  return new Response(generateLoginHTML("前台登录", "/login"), {
    headers: { "Content-Type": "text/html" }
  });
}

async function handleAdminLogin(request) {
  console.log("Handling admin login request");
  console.log("Request method:", request.method);

  if (request.method === "POST") {
    console.log("Processing POST request for admin login");
    const formData = await request.formData();
    console.log("Form data:", formData);
    const password = formData.get("password");
    console.log("Entered admin password:", password);
    console.log("Expected admin password:", ADMIN_PASSWORD);

    if (password === ADMIN_PASSWORD) {
      return new Response("Admin login successful", {
        status: 302,
        headers: {
          "Location": "/admin",
          "Set-Cookie": `admin_token=${ADMIN_PASSWORD}; HttpOnly; Path=/; SameSite=Strict`
        }
      });
    } else {
      return new Response(generateLoginHTML("后台登录", "/admin-login", "密码错误，请重试。"), {
        headers: { "Content-Type": "text/html" },
        status: 401
      });
    }
  }

  return new Response(generateLoginHTML("后台登录", "/admin-login"), {
    headers: { "Content-Type": "text/html" }
  });
}

async function handleApiUpdate(request) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const auth = request.headers.get("Authorization");
  if (!auth || auth !== `Basic ${btoa(`:${ADMIN_PASSWORD}`)}`) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    const data = await request.json();
    const { action, domain, system, registrar, registrationDate, expirationDate, apiKey, index } = data;

    if (action === 'add-api-key') {
      CF_API_KEYS.push(apiKey);
      // 这里你需要将更新后的 API 密钥列表保存到某个持久化存储中
      await KV_NAMESPACE.put('cf_api_keys', JSON.stringify(CF_API_KEYS));
    } else if (action === 'delete-api-key') {
      CF_API_KEYS.splice(index, 1);
      // 同样，这里你需要更新持久化存储
      await KV_NAMESPACE.put('cf_api_keys', JSON.stringify(CF_API_KEYS));
    } else if (action === 'delete') {
      // 删除自定义域名
      await KV_NAMESPACE.delete(`whois_${domain}`);
    } else if (action === 'update-whois') {
      // 更新 WHOIS 信息
      const whoisInfo = await fetchWhoisInfo(domain);
      await cacheWhoisInfo(domain, whoisInfo);
    } else if (action === 'add') {
      // 添加新域名
      const newDomainInfo = {
        domain,
        system,
        registrar,
        registrationDate,
        expirationDate,
        isCustom: true
      };
      await cacheWhoisInfo(domain, newDomainInfo);
    } else {
      // 更新域名信息
      let domainInfo = await getCachedWhoisInfo(domain) || {};
      domainInfo = {
        ...domainInfo,
        registrar,
        registrationDate,
        expirationDate
      };
      await cacheWhoisInfo(domain, domainInfo);
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error in handleApiUpdate:', error);
    return new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function fetchCloudflareDomainsInfo() {
  let allDomains = [];

  for (let i = 0; i < CF_API_KEYS.length; i++) {
    const apiKey = CF_API_KEYS[i];
    const username = USERNAMES[i]; // 获取对应的用户名

    try {
      const response = await fetch('https://api.cloudflare.com/client/v4/zones', {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        console.error(`Failed to fetch domains for API key: ${apiKey}`);
        continue;
      }

      const data = await response.json();
      if (!data.success) {
        console.error(`Cloudflare API request failed for API key: ${apiKey}`);
        continue;
      }

      const domains = data.result.map(zone => ({
        domain: zone.name,
        registrationDate: new Date(zone.created_on).toISOString().split('T')[0],
        system: 'Cloudflare',
        apiKey: apiKey, // 添加 apiKey 字段
        username: username // 添加用户名字段
      }));

      allDomains = allDomains.concat(domains);
    } catch (error) {
      console.error(`Error fetching domains for API key: ${apiKey}`, error);
    }
  }

  return allDomains;
}

async function fetchDomainInfo(domains) {
  const result = [];
  
  // 获取所有域名信息，包括自定义域名
  const allDomainKeys = await KV_NAMESPACE.list({ prefix: 'whois_' });
  const allDomains = await Promise.all(allDomainKeys.keys.map(async (key) => {
    const value = await KV_NAMESPACE.get(key.name);
    if (value) {
      try {
        const parsedValue = JSON.parse(value);
        return parsedValue.data;
      } catch (error) {
        console.error(`Error parsing data for ${key.name}:`, error);
        return null;
      }
    }
    return null;
  }));

  // 过滤掉无效的域名数据
  const validAllDomains = allDomains.filter(d => d && d.isCustom);

  // 合并 Cloudflare 域名和自定义域名
  const mergedDomains = [...domains, ...validAllDomains];
  
  for (const domain of mergedDomains) {
    if (!domain) continue; // 跳过无效的域名数据

    let domainInfo = { ...domain };

    const cachedInfo = await getCachedWhoisInfo(domain.domain || domain);
    if (cachedInfo) {
      domainInfo = { ...domainInfo, ...cachedInfo };
    } else if (!domainInfo.isCustom && domainInfo.domain && domainInfo.domain.split('.').length === 2 && WHOIS_PROXY_URL) {
      try {
        const whoisInfo = await fetchWhoisInfo(domainInfo.domain);
        domainInfo = { ...domainInfo, ...whoisInfo };
        if (!whoisInfo.whoisError) {
          await cacheWhoisInfo(domainInfo.domain, whoisInfo);
        }
      } catch (error) {
        console.error(`Error fetching WHOIS info for ${domainInfo.domain}:`, error);
        domainInfo.whoisError = error.message;
      }
    }

    result.push(domainInfo);
  }
  return result;
}

async function handleWhoisRequest(domain) {
  console.log(`Handling WHOIS request for domain: ${domain}`);

  try {
    console.log(`Fetching WHOIS data from: ${WHOIS_PROXY_URL}/whois/${domain}`);
    const response = await fetch(`${WHOIS_PROXY_URL}/whois/${domain}`);
    
    if (!response.ok) {
      throw new Error(`WHOIS API responded with status: ${response.status}`);
    }
    
    const whoisData = await response.json();
    console.log(`Received WHOIS data:`, whoisData);
    
    return new Response(JSON.stringify({
      error: false,
      rawData: whoisData.rawData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error(`Error fetching WHOIS data for ${domain}:`, error);
    return new Response(JSON.stringify({
      error: true,
      message: `Failed to fetch WHOIS data for ${domain}. Error: ${error.message}`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function fetchWhoisInfo(domain) {
  try {
    const response = await fetch(`${WHOIS_PROXY_URL}/whois/${domain}`);
    const whoisData = await response.json();

    console.log('Raw WHOIS proxy response:', JSON.stringify(whoisData, null, 2));

    if (whoisData) {
      return {
        registrar: whoisData.registrar || 'Unknown',
        registrationDate: formatDate(whoisData.creationDate) || 'Unknown',
        expirationDate: formatDate(whoisData.expirationDate) || 'Unknown'
      };
    } else {
      console.warn(`Incomplete WHOIS data for ${domain}`);
      return {
        registrar: 'Unknown',
        registrationDate: 'Unknown',
        expirationDate: 'Unknown',
        whoisError: 'Incomplete WHOIS data'
      };
    }
  } catch (error) {
    console.error('Error fetching WHOIS info:', error);
    return {
      registrar: 'Unknown',
      registrationDate: 'Unknown',
      expirationDate: 'Unknown',
      whoisError: error.message
    };
  }
}

function formatDate(dateString) {
  if (!dateString) return null;
  const date = new Date(dateString);
  return isNaN(date.getTime()) ? dateString : date.toISOString().split('T')[0];
}

async function getCachedWhoisInfo(domain) {
  const cacheKey = `whois_${domain}`;
  const cachedData = await KV_NAMESPACE.get(cacheKey);
  if (cachedData) {
    const { data, timestamp } = JSON.parse(cachedData);
    // 检查是否有错误内容，如果有，删除它
    if (data.whoisError) {
      await KV_NAMESPACE.delete(cacheKey);
      return null;
    }
    // 这里可以添加缓存过期检查，如果需要的话
    return data;
  }
  return null;
}

async function cacheWhoisInfo(domain, whoisInfo) {
  const cacheKey = `whois_${domain}`;
  await KV_NAMESPACE.put(cacheKey, JSON.stringify({
    data: whoisInfo,
    timestamp: Date.now()
  }));
}

function generateLoginHTML(title, action, errorMessage = "") {
  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <link rel="shortcut icon" href="https://img4.anyhub.us.kg/i/2024/1/1526a0af2f66abd8.png">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - ${CUSTOM_TITLE}</title>
    <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 20px;
      background-color: #f4f4f4;
    }
    .container {
      max-width: 1600px;
      width: 100%;
      margin: 0 auto;
      background-color: #fff;
      padding: 20px;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
      margin-bottom: 60px;
    }
    .login-container {
      max-width: 300px;
      text-align: center;
      margin: 80px auto;
      padding: 20px;
      background-color: #fff;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }
    input[type="password"], input[type="submit"] {
      width: 100%;
      padding: 10px;
      margin: 10px 0;
    }
    input[type="submit"] {
      background-color: #4CAF50;
      color: white;
      border: none;
      cursor: pointer;
    }
    input[type="submit"]:hover {
      background-color: #45a049;
    }
    .error-message {
      color: red;
    }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h1 style="text-align: center;color: #03a9f4;">${title}</h1>
      ${errorMessage ? `<p class="error-message">${errorMessage}</p>` : ''}
      <form method="POST" action="${action}">
        <input type="password" name="password" style="width: 92%;padding: 8px 10px;" placeholder="请输入密码" required>
        <input type="submit" value="登录">
      </form>
    </div>
    ${footerHTML}
  </body>
  </html>
  `;
}

function getStatusColor(daysRemaining) {
  if (daysRemaining === 'N/A' || daysRemaining <= 0) return '#e74c3c'; // 红色
  if (daysRemaining <= 30) return '#f1c40f'; // 黄色
  return '#2ecc71'; // 绿色
}

function getStatusTitle(daysRemaining) {
  if (daysRemaining === 'N/A') return '无效的到期日期';
  if (daysRemaining <= 0) return '已过期';
  if (daysRemaining <= 30) return '即将过期';
  return '正常';
}

function generateHTML(domains, isAdmin) {




  const groupedDomains = {};
  domains.forEach(domain => {
    const key = domain.apiKey; // 假设每个域名有对应的 apiKey
    if (!groupedDomains[key]) {
      groupedDomains[key] = [];
    }
    groupedDomains[key].push(domain);
  });

  const generateTable = (domainList) => `
    <table>
      <thead>
        <tr>
          <th class="status-column">状态</th>
          <th class="domain-column">域名</th>
          <th class="system-column">系统</th>
          <th class="registrar-column">注册商</th>
          <th class="date-column">注册日期</th>
          <th class="date-column">到期日期</th>
          <th class="days-column">剩余天数</th>
          <th class="progress-column">进度</th>
          ${isAdmin ? '<th class="operation-column">操作</th>' : ''}
        </tr>
      </thead>
      <tbody>
        ${domainList.map(domain => {
          const now = new Date();
          const expirationDate = new Date(domain.expirationDate);
          const registrationDate = new Date(domain.registrationDate);
          const totalDays = (expirationDate - registrationDate) / (1000 * 60 * 60 * 24);
          const daysRemaining = Math.ceil((expirationDate - now) / (1000 * 60 * 60 * 24));
          const progress = ((totalDays - daysRemaining) / totalDays) * 100;

          const statusColor = getStatusColor(daysRemaining);
          const statusTitle = getStatusTitle(daysRemaining);

          return `
            <tr>
              <td class="status-column">
                <span class="status-dot" style="background-color: ${statusColor};" title="${statusTitle}"></span>
              </td>
              <td class="domain-column">${domain.domain}</td>
              <td class="system-column">${domain.system || 'N/A'}</td>
              <td class="registrar-column">${domain.registrar || 'N/A'}</td>
              <td class="date-column">${domain.registrationDate || 'N/A'}</td>
              <td class="date-column">${domain.expirationDate || 'N/A'}</td>
              <td class="days-column">${daysRemaining > 0 ? daysRemaining : 'N/A'}</td>
              <td class="progress-column">
                <div class="progress-bar">
                  <div class="progress" style="width: ${progress}%;"></div>
                </div>
              </td>
              ${isAdmin ? `
                <td class="operation-column">
                  <button onclick="editDomain('${domain.domain}', this)">编辑</button>
                  <button onclick="updateWhois('${domain.domain}')">更新WHOIS</button>
                  ${domain.isCustom ? `<button onclick="deleteDomain('${domain.domain}')">删除</button>` : ''}
                </td>
              ` : ''}
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;

  const apiKeyCount = CF_API_KEYS.length;

  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="shortcut icon" href="https://img4.anyhub.us.kg/i/2024/1/1526a0af2f66abd8.png">
    <title>${CUSTOM_TITLE}${isAdmin ? ' - ADMIN' : ''}</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        line-height: 1.6;
        margin: 0;
        padding: 20px;
        background-color: #f4f4f4;
      }
      .container {
        max-width: 1600px;
        width: 100%;
        margin: 0 auto;
        background-color: #fff;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        margin-bottom: 60px;
      }
      .table-wrapper {
        overflow-x: auto;
        width: 100%;
      }
      table {
        width: 100%;
        table-layout: auto;
      }
      thead {
        position: sticky;
        top: 0;
        background-color: #f2f2f2;
        z-index: 1;
      }
      th, td {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        text-align: center;
        border-bottom: #e1e1e1 1px solid;
        padding: 8px;
      }
      .status-column { width: 30px; }
      .domain-column { max-width: 200px; }
      .system-column, .registrar-column { max-width: 150px; }
      .date-column { max-width: 100px; }
      .days-column { max-width: 80px; }
      .progress-column { max-width: 150px; }
      .operation-column { max-width: 200px; }
      .status-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
      }
      .progress-bar {
        width: 100%;
        background-color: #e0e0e0;
        /*border-radius: 5px;*/
        overflow: hidden;
      }
      .progress {
        height: 15px;
        background-color: #4CAF50;
        transition: width 0.5s ease-in-out;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1 style="text-align: center;color: #ffffff;background-color: #03a9f4;padding: 20px;margin: -20px -20px 30px -20px;border-radius: 10px 10px 0 0;">${CUSTOM_TITLE}${isAdmin ? ' - ADMIN' : ''}</h1>
      ${Object.entries(groupedDomains).map(([key, domainList]) => {
        const username = domainList[0]?.username || '未知账户'; // 显示对应的用户名
        return `
          <h2 style="text-align: center;color: #673AB7">账户: ${username}</h2>
          <div class="table-wrapper">
            ${generateTable(domainList)}
          </div>
        `;
      }).join('')}
      
      ${isAdmin ? `
        <h2 style="text-align: center;color: #673AB7">添加新域名</h2>
        <form id="addDomainForm">
          <input type="text" id="newDomain" placeholder="域名" required>
          <input type="text" id="newSystem" placeholder="系统">
          <input type="text" id="newRegistrar" placeholder="注册商">
          <input type="date" id="newRegistrationDate" placeholder="注册日期">
          <input type="date" id="newExpirationDate" placeholder="到期日期">
          <button type="submit">添加域名</button>
        </form>

        <h2 style="text-align: center;color: #673AB7">管理 Cloudflare API 密钥</h2>
        <form id="addApiKeyForm">
          <input type="text" id="newApiKey" placeholder="新的 API 密钥" required>
          <button type="submit">添加 API 密钥</button>
        </form>
        <div id="apiKeyList">
          ${CF_API_KEYS.map((key, index) => `
            <div>
              API 密钥 ${index + 1}: ${key.slice(0, 10)}...
              <button onclick="deleteApiKey(${index})">删除</button>
            </div>
          `).join('')}
        </div>
      ` : ''}
    </div>
    ${isAdmin ? `
    <script>
    async function editDomain(domain, button) {
      const row = button.closest('tr');
      const cells = row.querySelectorAll('td');
      
      if (button.textContent === '编辑') {
        button.textContent = '保存';
        cells[2].innerHTML = '<input type="text" value="' + cells[2].textContent + '">';
        cells[3].innerHTML = '<input type="text" value="' + cells[3].textContent + '">';
        cells[4].innerHTML = '<input type="date" value="' + cells[4].textContent + '">';
        cells[5].innerHTML = '<input type="date" value="' + cells[5].textContent + '">';
      } else {
        button.textContent = '编辑';
        const updatedData = {
          domain: domain,
          system: cells[2].querySelector('input').value,
          registrar: cells[3].querySelector('input').value,
          registrationDate: cells[4].querySelector('input').value,
          expirationDate: cells[5].querySelector('input').value
        };
        const response = await fetch('/api/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
          },
          body: JSON.stringify(updatedData)
        });
        if (response.ok) {
          cells[2].textContent = updatedData.system;
          cells[3].textContent = updatedData.registrar;
          cells[4].textContent = updatedData.registrationDate;
          cells[5].textContent = updatedData.expirationDate;
        } else {
          alert('更新失败');
        }
      }
    }
    async function updateWhois(domain) {
      const response = await fetch('/api/update', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
        },
        body: JSON.stringify({ action: 'update-whois', domain: domain })
      });
      if (response.ok) {
        alert('WHOIS 信息更新成功');
        location.reload();
      } else {
        alert('WHOIS 信息更新失败');
      }
    }
    async function deleteDomain(domain) {
      if (confirm('确定要删除该域名吗？')) {
        const response = await fetch('/api/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
          },
          body: JSON.stringify({ action: 'delete', domain: domain })
        });
        if (response.ok) {
          alert('域名删除成功');
          location.reload();
        } else {
          alert('域名删除失败');
        }
      }
    }
    document.getElementById('addDomainForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const newDomain = document.getElementById('newDomain').value;
      const newSystem = document.getElementById('newSystem').value;
      const newRegistrar = document.getElementById('newRegistrar').value;
      const newRegistrationDate = document.getElementById('newRegistrationDate').value;
      const newExpirationDate = document.getElementById('newExpirationDate').value;
      const response = await fetch('/api/update', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
        },
        body: JSON.stringify({
          action: 'add',
          domain: newDomain,
          system: newSystem,
          registrar: newRegistrar,
          registrationDate: newRegistrationDate,
          expirationDate: newExpirationDate
        })
      });
      if (response.ok) {
        alert('新域名添加成功');
        location.reload();
      } else {
        alert('新域名添加失败');
      }
    });
    document.getElementById('addApiKeyForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const newApiKey = document.getElementById('newApiKey').value;
      const response = await fetch('/api/update', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
        },
        body: JSON.stringify({
          action: 'add-api-key',
          apiKey: newApiKey
        })
      });
      if (response.ok) {
        alert('新 API 密钥添加成功');
        location.reload();
      } else {
        alert('新 API 密钥添加失败');
      }
    });
    async function deleteApiKey(index) {
      if (confirm('确定要删除该 API 密钥吗？')) {
        const response = await fetch('/api/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
          },
          body: JSON.stringify({
            action: 'delete-api-key',
            index: index
          })
        });
        if (response.ok) {
          alert('API 密钥删除成功');
          location.reload();
        } else {
          alert('API 密钥删除失败');
        }
      }
    }
    </script>
    ` : ''}
    ${footerHTML}
  </body>
  </html>
  `;
}


function categorizeDomains(domains) {
  const categories = {
    '已过期': [],
    '30天内过期': [],
    '90天内过期': [],
    '正常': []
  };

  domains.forEach(domain => {
    const now = new Date();
    const expirationDate = new Date(domain.expirationDate);
    const daysRemaining = Math.ceil((expirationDate - now) / (1000 * 60 * 60 * 24));

    if (daysRemaining <= 0) {
      categories['已过期'].push(domain);
    } else if (daysRemaining <= 30) {
      categories['30天内过期'].push(domain);
    } else if (daysRemaining <= 90) {
      categories['90天内过期'].push(domain);
    } else {
      categories['正常'].push(domain);
    }
  });

  return categories;
}
