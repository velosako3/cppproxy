const https = require('https');
const fs    = require('fs');

function post(host, path, body) {
  return new Promise((resolve, reject) => {
    const data = body;
    const req = https.request({
      hostname: host, path, method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    }, res => {
      let s = ''; res.on('data', c => s += c);
      res.on('end', () => { try { resolve(JSON.parse(s)); } catch { resolve(s); } });
    });
    req.on('error', reject); req.write(data); req.end();
  });
}

function postJson(host, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request({
      hostname: host, path, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    }, res => {
      let s = ''; res.on('data', c => s += c);
      res.on('end', () => { try { resolve(JSON.parse(s)); } catch { resolve(s); } });
    });
    req.on('error', reject); req.write(data); req.end();
  });
}

function get(host, path, headers) {
  return new Promise((resolve, reject) => {
    https.get({ hostname: host, path, headers }, res => {
      let s = ''; res.on('data', c => s += c);
      res.on('end', () => { try { resolve(JSON.parse(s)); } catch { resolve(s); } });
    }).on('error', reject);
  });
}

async function main() {
  console.log('Getting device code...');
  const dev = await post(
    'login.live.com',
    '/oauth20_connect.srf',
    'client_id=00000000402b5328&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=device_code'
  );
  if (!dev.user_code) throw new Error('Device code failed: ' + JSON.stringify(dev));

  console.log(`\n  Go to: ${dev.verification_uri}`);
  console.log(`  Code:  ${dev.user_code}\n`);
  console.log('Waiting for you to log in...');

  let msToken;
  while (true) {
    await new Promise(r => setTimeout(r, (dev.interval || 5) * 1000));
    const t = await post(
      'login.live.com',
      '/oauth20_token.srf',
      `client_id=00000000402b5328&device_code=${dev.device_code}&grant_type=urn:ietf:params:oauth:grant-type:device_code`
    );
    if (t.access_token) { msToken = t; break; }
    if (t.error && t.error !== 'authorization_pending')
      throw new Error('Login failed: ' + (t.error_description || t.error));
  }
  console.log('Microsoft OK');

  const xbl = await postJson(
    'user.auth.xboxlive.com',
    '/user/authenticate',
    { Properties: { AuthMethod: 'RPS', SiteName: 'user.auth.xboxlive.com', RpsTicket: `t=${msToken.access_token}` },
      RelyingParty: 'http://auth.xboxlive.com', TokenType: 'JWT' }
  );
  if (!xbl.Token) throw new Error('XBL failed: ' + JSON.stringify(xbl));
  console.log('Xbox Live OK');

  const xsts = await postJson(
    'xsts.auth.xboxlive.com',
    '/xsts/authorize',
    { Properties: { SandboxId: 'RETAIL', UserTokens: [xbl.Token] },
      RelyingParty: 'rp://api.minecraftservices.com/', TokenType: 'JWT' }
  );
  if (!xsts.Token) throw new Error('XSTS failed: ' + JSON.stringify(xsts));
  const userHash = xbl.DisplayClaims.xui[0].uhs;
  console.log('XSTS OK');

  const mc = await postJson(
    'api.minecraftservices.com',
    '/authentication/login_with_xbox',
    { identityToken: `XBL3.0 x=${userHash};${xsts.Token}` }
  );
  if (!mc.access_token) throw new Error('Minecraft auth failed: ' + JSON.stringify(mc));
  console.log('Minecraft OK');

  const profile = await get(
    'api.minecraftservices.com',
    '/minecraft/profile',
    { 'Authorization': `Bearer ${mc.access_token}` }
  );
  if (!profile.id) throw new Error('Profile failed: ' + JSON.stringify(profile));

  fs.writeFileSync('auth.json', JSON.stringify({
    accessToken: mc.access_token,
    uuid:        profile.id,
    username:    profile.name
  }, null, 2));

  console.log(`\nLogged in as: ${profile.name}`);
  console.log('Saved auth.json - run start.bat to launch proxy');
}

main().catch(e => { console.error('\nError:', e.message); process.exit(1); });
