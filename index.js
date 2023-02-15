addEventListener('fetch', event => {
  event.respondWith(
    handleRequest(event.request).catch(
      err => new Response(err.stack, { status: 500 }),
    ),
  );
});

async function handleRequest(request) {
  let { origin, pathname: path, searchParams: params } = new URL(request.url);

  if (!path.startsWith('/txt/')) {
    return Response.redirect(origin + '/txt/', 301);
  }

  if (path === '/txt/') {
    return Response.redirect(origin + '/txt/hutrua.txt', 301);
  }

  path = path.substring(5);
  path = path.endsWith('/') ? path.slice(0, -1) : path;

  if (request.method == 'POST') {
    return handlePost(request, path);
  }

  if (path === 'list') {
    return ListTxt();
  }

  if (path === 'upload') {
    return Upload();
  }

  if (path.startsWith('edit/')) {
    return Edit(path.substring(5), params);
  }

  if (path.startsWith('raw/')) {
    return handleRaw(path.substring(4), params);
  }

  return handleTxt(path, params);
}

function isValid(filename) {
  if (filename === null || filename === '' || filename === 'private') {
    return false;
  }
  if (filename.startsWith('private/')) {
    filename.substring(8);
  }
  return /^[a-z0-9_.@()-]+$/i.test(filename);
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function html_template(name, content) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${name}</title>
    <link rel="icon" type="image/png" href="/assets/images/favicon.png">
    <link rel="icon" type="image/svg+xml" href="/assets/images/favicon.svg">
    <link rel="apple-touch-icon" sizes="180x180" href="/assets/images/apple-touch-icon.png">
</head>
<body>
  <main>
    <h1>${name}</h1>
    ${content}
  </main>
  <footer>
    <p style='color:grey;font-size:0.7em;'>This page is generated by Cloudflare Workers.</p>
  </footer>
</body>
</html>`;
}

function ShowMessage(name, error) {
  error = error.split('\n');
  for (let i = 0; i < error.length; i++) {
    error[i] = '<p>' + escapeHtml(error[i]) + '</p>';
  }
  error = error.join('\n');
  return ShowHtml(name, error);
}

function ShowTxt(name, txt) {
  txt = txt.split('\n');
  for (let i = 0; i < txt.length; i++) {
    txt[i] = '<p>' + escapeHtml(txt[i]) + '</p>';
  }
  txt.push(`<a href="/txt/raw/${name}">raw</a>`);
  txt.push(`<a href="/txt/edit/${name}">edit</a>`);
  txt = txt.join('\n');
  return ShowHtml(name, txt);
}

function ShowHtml(name, html) {
  return new Response(html_template(name, html), {
    headers: { 'content-type': 'text/html;charset=UTF-8' },
  });
}

function ShowTxtPlain(name, txt) {
  return new Response(txt, {
    headers: { 'content-type': 'text/plain;charset=UTF-8' },
  });
}

async function ListTxt() {
  const v = await TXT.list();
  let list = [];
  for (let i = 0; i < v.keys.length; i++) {
    let name = v.keys[i].name;
    list.push(`<p><a href="/txt/${name}">${name}</a></p>\n`);
  }
  list.push(`<a href="/txt/upload">upload</a>`);
  list = list.join('\n');
  return ShowHtml('txt list', list);
}

async function Upload(request) {
  let upload_html = `
<form action="/txt/upload" method="POST">
  <div>
    <label for="filename">filename</label>
    <input type="txt" name="filename" id="filename">
  </div>
  <div>
    <textarea name="txt" rows="30" cols="80"></textarea>
  </div>
  <div>
    <label for="token">token</label>
    <input type="password" name="token" id="token">
  </div>
  <div>
    <input type="submit" value="Upload">
  </div>
</form>
`;
  return ShowHtml('upload', upload_html);
}

async function Edit(filename, params) {
  if (!isValid(filename)) {
    return ShowMessage('edit', `invalid filename`);
  }
  if (filename.startsWith('private/')) {
    let token = params.get('token');
    if (!(await validToken(token))) {
      private_html = `<p>private file</p>
<form action="/txt/edit/${filename}" method="GET">
  <div>
    <label for="token">token</label>
    <input type="password" name="token" id="token">
  </div>
  <div>
    <input type="submit" value="Edit">
  </div>
</form>`;
      return ShowHtml(filename, private_html);
    }
  }

  const txt = await TXT.get(filename);
  if (txt === null) {
    return ShowMessage('edit', `file ${filename} does not exist`);
  }

  let edit_html = `<form method="POST">
  <div>
    <label for="filename">filename</label>
    <input type="txt" name="filename" id="filename" value="${filename}" readonly>
  </div>
  <div>
    <textarea name="txt" rows="30" cols="80">${txt}</textarea>
  </div>
  <div>
  <label for="token">token</label>
  <input type="password" name="token" id="token">
  </div>
  <div>
    <input type="submit" value="Update" formaction="/txt/edit">
    <input type="submit" value="Delete" formaction="/txt/delete">
  </div>
</form>`;
  return ShowHtml('edit', edit_html);
}

async function validToken(token) {
  const salted_token = new TextEncoder().encode('User input token: ' + token);
  const sha = await crypto.subtle.digest('SHA-512', salted_token);
  const sha_hex = new Uint8Array(sha).reduce(
    (a, b) => a + b.toString(16).padStart(2, '0'),
    '',
  );

  const correct_hex =
    '4bc007f98d52df91d989360911663d29' +
    '51dfbffc2296a456aa053152b4527b62' +
    '3686b07262169225460749a0327d7541' +
    'd6ee433b9408f4f88868ce265beae91a';

  return sha_hex === correct_hex;
}

async function handlePost(request, path) {
  form = await request.formData();

  if (!(await validToken(form.get('token')))) {
    return ShowMessage(path, `invalid token`);
  }

  let name = form.get('filename');
  if (!isValid(name)) {
    return ShowMessage(path, `invalid filename`);
  }

  let txt = form.get('txt');
  const v = await TXT.get(name);

  if (path === 'upload') {
    if (v !== null) {
      return ShowMessage(path, `file ${name} already exists`);
    } else {
      await TXT.put(name, txt);
      return ShowTxt(name, txt);
    }
  }

  if (v === null) {
    return ShowMessage(path, `file ${name} does not exist`);
  }

  if (path === 'edit') {
    await TXT.put(name, txt);
    return ShowTxt(name, txt);
  }

  if (path === 'delete') {
    await TXT.delete(name);
    return ShowMessage(path, `file ${name} deleted`);
  }

  return ShowMessage(path, `server error`);
}

async function handleRaw(path, params) {
  if (path.startsWith('private/')) {
    let token = params.get('token');
    if (!(await validToken(token))) {
      private_html = `<p>private file</p>
<form action="/txt/raw/${path}" method="GET">
  <div>
    <label for="token">token</label>
    <input type="password" name="token" id="token">
  </div>
  <div>
    <input type="submit" value="View">
  </div>
</form>`;
      return ShowHtml(path, private_html);
    }
  }

  let name = decodeURIComponent(path);
  if (!isValid(name)) {
    return ShowMessage(name, `invalid filename`);
  }
  let txt = await TXT.get(name);
  if (txt !== null) {
    return ShowTxtPlain(name, txt);
  }

  return ShowMessage('404', '404 not found');
}

async function handleTxt(path, params) {
  if (path.startsWith('private/')) {
    let token = params.get('token');
    if (!(await validToken(token))) {
      private_html = `<p>private file</p>
<form action="/txt/${path}" method="GET">
  <div>
    <label for="token">token</label>
    <input type="password" name="token" id="token">
  </div>
  <div>
    <input type="submit" value="View">
  </div>
</form>`;
      return ShowHtml(path, private_html);
    }
  }

  let name = decodeURIComponent(path);
  if (!isValid(name)) {
    return ShowMessage(name, `invalid filename`);
  }
  let txt = await TXT.get(name);
  if (txt !== null) {
    return ShowTxt(name, txt);
  }

  return ShowMessage('404', '404 not found');
}
