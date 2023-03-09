import { marked } from 'marked';
import mustache from 'mustache';

addEventListener('fetch', event => {
  event.respondWith(
    handleRequest(event.request).catch(
      err => new Response(err.stack, { status: 500 }),
    ),
  );
});

async function handleRequest(request) {
  let { origin, pathname: path } = new URL(request.url);

  let entry = origin + '/txt/';

  if (!path.startsWith('/txt/')) {
    return Response.redirect(entry, 301);
  }

  if (path === '/txt/') {
    return Response.redirect(entry + 'hutrua.txt', 301);
  }

  path = path.substring(5);
  path = path.endsWith('/') ? path.slice(0, -1) : path;

  if (request.method == 'POST') {
    return handlePost(request, entry, path);
  }

  if (path === 'list') {
    return ListTxt();
  }

  if (path === 'upload') {
    if (!(await loggedIn(request.headers))) {
      return ShowLogin(path);
    }

    let upload_html = await TXT.get('upload.html');
    return ShowHtml('upload', upload_html);
  }

  if (path === 'upload_file') {
    if (!(await loggedIn(request.headers))) {
      return ShowLogin(path);
    }

    let upload_html = await TXT.get('upload_file.html');
    return ShowHtml('upload file', upload_html);
  }

  return handleGet(path, request.headers);
}

function isValid(filename) {
  if (!filename) {
    return false;
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

async function ShowMessage(name, msg) {
  msg = msg.split('\n');
  for (let i = 0; i < msg.length; i++) {
    msg[i] = `<p>${escapeHtml(msg[i])}</p>`;
  }
  msg = msg.join('\n');
  return ShowHtml(name, msg);
}

async function ShowLogin(path) {
  let private_template = await TXT.get('login.html');
  private_html = mustache.render(private_template, {
    path: path,
  });
  return ShowHtml(path, private_html);
}

async function ShowTxt(name, txt) {
  if (name.endsWith('.md')) {
    txt = marked.parse(txt);
  } else {
    txt = txt
      .replace(/^\s+|\r|\s+$/g, '')
      .replace(/\t/g, '    ')
      .split('\n');
    for (let i = 0; i < txt.length; i++) {
      txt[i] = txt[i] ? `<p>${escapeHtml(txt[i])}</p>` : '<br>';
    }
    txt = txt.join('\n');
  }
  txt += `<a href="/txt/raw/${name}">raw</a>\n`;
  txt += `<a href="/txt/edit/${name}">edit</a>\n`;
  return ShowHtml(name, txt);
}

async function ShowHtml(name, content) {
  let page_template = await TXT.get('page.html');
  return new Response(
    mustache.render(page_template, { name: name, content: content }),
    {
      headers: { 'content-type': 'text/html;charset=UTF-8' },
    },
  );
}

async function ShowTxtPlain(name, txt) {
  return new Response(txt, {
    headers: { 'content-type': 'text/plain;charset=UTF-8' },
  });
}

async function ShowBin(name, bin) {
  if (!bin) {
    let bin_html = `<p>binary file</p>\n`;
    bin_html += `<a href="/txt/raw/${name}">download</a>\n`;
    bin_html += `<a href="/txt/edit/${name}">edit</a>\n`;
    return ShowHtml(name, bin_html);
  }
  return new Response(bin, {
    headers: {
      'content-type': 'application/octet-stream',
      'content-disposition': 'attachment',
    },
  });
}

async function ListTxt() {
  const { keys, list_complete } = await TXT.list();
  let list_template = await TXT.get('list.html');
  txts = keys.map(key => {
    let txt = {
      name: key.name,
      timestamp: '-',
      type: 'txt',
      private: 'y',
      temp: '',
      expiration: '',
    };
    if (key.metadata) {
      txt.timestamp = new Date(key.metadata.timestamp)
        .toISOString()
        .split('T')[0];
      txt.type = key.metadata.is_bin ? 'binary' : 'txt';
      txt.private = key.metadata.is_private ? 'y' : '';
    }
    if (key.expiration) {
      txt.temp = 'y';
      txt.expiration = key.expiration + ' seconds';
    }
    return txt;
  });
  return ShowHtml('txt list', mustache.render(list_template, { txts: txts }));
}

async function validToken(token) {
  const salted_token = new TextEncoder().encode('User input token: ' + token);
  const sha = await crypto.subtle.digest('SHA-512', salted_token);
  const sha_hex = new Uint8Array(sha).reduce(
    (a, b) => a + b.toString(16).padStart(2, '0'),
    '',
  );

  const correct_hex = await TXT.get('TOKEN');

  return sha_hex === correct_hex;
}

async function loggedIn(headers) {
  let cookies = {};
  headers.get('Cookie') &&
    headers
      .get('Cookie')
      .split(';')
      .map(v => v.split('='))
      .forEach(v => (cookies[v[0]] = v[1]));
  let token = cookies['token'];
  return await validToken(token);
}

async function handlePost(request, entry, path) {
  const form = await request.formData();

  if (path === 'login') {
    const token = form.get('token');
    const redirect_path = form.get('path');
    if (!(await validToken(token))) {
      return ShowMessage(path, `invalid token`);
    } else {
      // login expires in 1 hour
      expire_date = new Date(Date.now() + 3600 * 1000).toUTCString();
      return new Response(
        `<meta http-equiv="Refresh" content="0; URL=${entry +
          redirect_path}" />ok`,
        {
          headers: {
            'content-type': 'text/html;charset=UTF-8',
            'set-cookie': `token=${token}; path=/txt/; expires=${expire_date}; HttpOnly;`,
          },
        },
      );
    }
  }

  if (!(await loggedIn(request.headers))) {
    return ShowLogin(path);
  }

  let name, txt;
  let metadata = {
    is_private: true,
    is_bin: false,
    timestamp: Date.now(),
  };
  metadata.is_private = form.get('is_private') === 'true';
  metadata.is_bin = form.get('is_bin') === 'true';

  if (path === 'upload_file') {
    const file = form.get('file-to-upload');
    if (file.size === 0) {
      return ShowMessage(path, `invalid file`);
    }
    name = file.name;
    txt = metadata.is_bin ? await file.stream() : await file.text();
  } else {
    name = form.get('filename');
    txt = form.get('txt');
  }

  if (!isValid(name)) {
    return ShowMessage(path, `invalid filename`);
  }
  const v = await TXT.get(name);

  if (path === 'upload' || path === 'upload_file') {
    if (v !== null) {
      return ShowMessage(path, `file ${name} already exists`);
    } else {
      await TXT.put(name, txt, { metadata: metadata });
      return Response.redirect(entry + name, 303);
    }
  }

  if (v === null) {
    return ShowMessage(path, `file ${name} does not exist`);
  }

  if (path === 'edit') {
    if (metadata.is_bin) {
      // only change metadata
      await TXT.put(name, v, { metadata: metadata });
    } else {
      await TXT.put(name, txt, { metadata: metadata });
    }
    return Response.redirect(entry + name, 303);
  }

  if (path === 'delete') {
    await TXT.delete(name);
    return ShowMessage(path, `file ${name} deleted`);
  }

  return ShowMessage(path, `server error`);
}

async function handleGet(path, headers) {
  let name, type;
  if (path.startsWith('edit/')) {
    type = 'Edit';
    name = path.substring(5);
  } else if (path.startsWith('raw/')) {
    type = 'View Raw';
    name = path.substring(4);
  } else {
    type = 'View';
    name = path;
  }
  name = decodeURIComponent(name);
  if (!isValid(name)) {
    return ShowMessage('404', '404 not found');
  }
  const { value: txt, metadata } = await TXT.getWithMetadata(name);
  if (txt === null) {
    return ShowMessage('404', '404 not found');
  }

  if (metadata === null || metadata.is_private || type === 'Edit') {
    if (!(await loggedIn(headers))) {
      return ShowLogin(path);
    }
  }

  if (metadata && metadata.is_bin) {
    if (type == 'Edit') {
      let edit_template = await TXT.get('edit_bin.html');
      return ShowHtml(
        'edit',
        mustache.render(edit_template, {
          filename: name,
          is_private: metadata ? metadata.is_private : true,
        }),
      );
    } else if (type === 'View Raw') {
      const bin = await TXT.get(name, { type: 'stream' });
      return ShowBin(name, bin);
    } else {
      // type === 'View'
      return ShowBin(name);
    }
  }

  if (type === 'Edit') {
    let edit_template = await TXT.get('edit.html');
    return ShowHtml(
      'edit',
      mustache.render(edit_template, {
        filename: name,
        txt: txt,
        is_private: metadata ? metadata.is_private : true,
      }),
    );
  } else if (type === 'View Raw') {
    return ShowTxtPlain(name, txt);
  } else {
    // type === 'View'
    return ShowTxt(name, txt);
  }
}
