addEventListener('fetch', event => {
  event.respondWith(
    handleRequest(event.request).catch(
      err => new Response(err.stack, { status: 500 }),
    ),
  );
});

async function handleRequest(request) {
  const { origin, pathname } = new URL(request.url);

  if (!pathname.startsWith('/txt/') || pathname === '/txt/' || pathname === '/txt/index.html') {
    return Response.redirect(origin + '/txt/hutrua', 301);
  }

  if (pathname === '/txt/list' || pathname === '/txt/list/') {
    return ListTxt();
  }

  if (pathname.endsWith('.txt')) {
    let name = decodeURIComponent(pathname.substr(5));
    let txt = await TXT.get(name);
    if (txt !== null) {
      return ShowTxtPlain(name, txt);
    }
  } else {
    let name = decodeURIComponent(pathname.substr(5)) +'.txt';
    let txt = await TXT.get(name);
    if (txt !== null) {
      return ShowTxt(name, txt);
    }
  }

  return ShowTxt('404', '404 not found');
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
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

async function ShowTxt(name, txt) {
  txt = txt.split('\n');
  for (let i = 0; i < txt.length; i++) {
    txt[i] = '<p>' + escapeHtml(txt[i]) + '</p>';
  }
  txt = txt.join('\n');
  txt += `<a href="${name}">raw</a>\n`;
  return new Response(html_template(name, txt), {
    headers: { 'content-type': 'text/html;charset=UTF-8' },
  });
}

async function ShowTxtPlain(name, txt) {
  return new Response(txt, {
    headers: { 'content-type': 'text/plain;charset=UTF-8' },
  });
}

async function ListTxt() {
  const v = await TXT.list();
  let list = [];
  for(let i = 0; i < v.keys.length; i++) {
    let name = v.keys[i].name;
    list.push(`<p><a href="/txt/${name.slice(0, -4)}">${name}</a></p>\n`);
  }
  list = list.join('\n');
  return new Response(html_template('txt list', list), {
    headers: { 'content-type': 'text/html;charset=UTF-8' },
  });
}
