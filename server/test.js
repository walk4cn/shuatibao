// 端到端自测：注册 -> 登录 -> 上传 -> 拉取 -> 旧时间戳不覆盖 -> 续期 -> 隔离 -> 静态托管
// 服务端启用 SYNC_API_KEY 时，所有 /auth/ 和 /rest/ 请求都必须带正确的 apikey。
const PORT = process.env.PORT || 8099;
const B = 'http://127.0.0.1:' + PORT;
const KEY = process.env.SYNC_API_KEY || '';
const useKey = !!KEY;
const AK = useKey ? KEY : 'x';   // 服务端没设 key 时，随便给一个即可
const email = 't' + Date.now() + '@a.com';
let ok = 0, bad = 0;
function chk(name, cond, extra) {
  if (cond) { ok++; console.log('PASS  ' + name); }
  else { bad++; console.log('FAIL  ' + name + (extra ? '  -> ' + JSON.stringify(extra) : '')); }
}
async function main() {
  // 若服务端启用了 key，未带 apikey 的接口应被拒 401
  if (useKey) {
    const r0 = await fetch(B + '/auth/v1/signup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: '123456' })
    });
    chk('未带 apikey 请求被拒 401', r0.status === 401, r0.status);
  }

  let r = await fetch(B + '/auth/v1/signup', {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: AK },
    body: JSON.stringify({ email, password: '123456' })
  });
  let j = await r.json();
  chk('注册返回 access_token/user.id', r.status === 201 && !!j.access_token && !!j.user.id, j);

  const at = j.access_token, rt = j.refresh_token, uid = j.user.id;

  r = await fetch(B + '/auth/v1/token?grant_type=password', {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: AK },
    body: JSON.stringify({ email, password: '123456' })
  });
  j = await r.json();
  chk('密码登录', r.status === 200 && !!j.access_token, j);
  chk('错误密码被拒', (await (await fetch(B + '/auth/v1/token?grant_type=password', {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: AK },
    body: JSON.stringify({ email, password: 'wrongpass' })
  })).json()).error !== undefined);

  r = await fetch(B + '/rest/v1/sync_data', { headers: { Authorization: 'Bearer ' + at, apikey: AK } });
  chk('未上传时拉取为空数组', r.status === 200 && (await r.json()).length === 0);

  const ts1 = new Date(Date.now() - 10000).toISOString();
  r = await fetch(B + '/rest/v1/sync_data', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, apikey: AK, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates' },
    body: JSON.stringify([{ user_id: uid, data_key: 'banks', payload: { v: '{"a":1}' }, updated_at: ts1 }])
  });
  chk('上传返回 201', r.status === 201, r.status);

  r = await fetch(B + '/rest/v1/sync_data', { headers: { Authorization: 'Bearer ' + at, apikey: AK } });
  let rows = await r.json();
  chk('拉取到 1 行且内容正确', rows.length === 1 && rows[0].data_key === 'banks' && rows[0].payload.v === '{"a":1}', rows);

  // 服务端时间戳为准：客户端传的 updated_at 被忽略，统一以服务器接收时间落库并返回
  await fetch(B + '/rest/v1/sync_data', {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, apikey: AK, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates' },
    body: JSON.stringify([{ user_id: uid, data_key: 'banks', payload: { v: '{"a":2}' }, updated_at: '1999-01-01T00:00:00.000Z' }])
  });
  const pushRes = await (await fetch(B + '/rest/v1/sync_data', {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, apikey: AK, 'Content-Type': 'application/json' },
    body: JSON.stringify([{ user_id: uid, data_key: 'banks', payload: { v: '{"a":STALE}' }, updated_at: '1999-01-01T00:00:00.000Z' }])
  })).json();
  chk('推送返回服务端落库时间', Array.isArray(pushRes) && pushRes[0] && /^\d{4}-/.test(pushRes[0].updated_at || '') && (pushRes[0].updated_at || '').indexOf('1999') === -1, pushRes[0]);
  rows = await (await fetch(B + '/rest/v1/sync_data', { headers: { Authorization: 'Bearer ' + at, apikey: AK } })).json();
  chk('后推送覆盖先推送（服务端时间为准）', rows[0].payload.v === '{"a":STALE}', rows[0]);

  j = await (await fetch(B + '/auth/v1/token?grant_type=refresh_token', {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: AK }, body: JSON.stringify({ refresh_token: rt })
  })).json();
  chk('refresh 换新 token 且含 user', !!j.access_token && !!j.user && j.user.id === uid, j);

  chk('旧 access_token 续期后仍可用（多设备）',
    (await fetch(B + '/rest/v1/sync_data', { headers: { Authorization: 'Bearer ' + at, apikey: AK } })).status === 200);

  chk('无 token 访问被拒 401',
    (await fetch(B + '/rest/v1/sync_data', { headers: { apikey: AK } })).status === 401);
  chk('伪造 token 被拒 401',
    (await fetch(B + '/rest/v1/sync_data', { headers: { Authorization: 'Bearer deadbeef', apikey: AK } })).status === 401);

  // 第二个用户数据隔离
  const e2 = 'u' + Date.now() + '@a.com';
  const j2 = await (await fetch(B + '/auth/v1/signup', {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: AK }, body: JSON.stringify({ email: e2, password: '123456' })
  })).json();
  const rows2 = await (await fetch(B + '/rest/v1/sync_data', { headers: { Authorization: 'Bearer ' + j2.access_token, apikey: AK } })).json();
  chk('用户间数据隔离', rows2.length === 0);
  chk('重复邮箱注册被拒', (await (await fetch(B + '/auth/v1/signup', {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: AK }, body: JSON.stringify({ email, password: '123456' })
  })).json()).error !== undefined);

  const home = await fetch(B + '/');
  const html = await home.text();
  chk('根路径返回 index.html', home.status === 200 && html.includes('云同步'));
  chk('不泄露 .git / server 目录',
    (await fetch(B + '/server/server.js')).status === 403 && (await fetch(B + '/.git/config')).status === 403);
  chk('/health 正常', (await (await fetch(B + '/health')).json()).ok === true);

  console.log('\n通过 ' + ok + ' 项，失败 ' + bad + ' 项');
  process.exit(bad ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(1); });
