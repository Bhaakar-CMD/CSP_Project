const https = require('https');

const vids = [
  { id: '01kXk8mmbPA', tag: 'Furrow Telugu' },
  { id: 'sH3jQ4ziQ_k', tag: 'Subsurface Telugu' },
  { id: 'BNJc6ZMOJ-w', tag: 'Drip Telugu' },
  { id: 'bUFBMCBv1xQ', tag: 'AWD Telugu' },
  { id: 'ebTydid4m80', tag: 'Sprinkler Telugu' },
  { id: 'e2fMOGuJ55U', tag: 'Surface Telugu' },
  { id: 'FZW9hULvOiI', tag: 'Fertigation Telugu' }
];

function fetchInfo(v) {
  return new Promise((resolve) => {
    const url = `https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=${v.id}&format=json`;
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ ...v, title: json.title, author: json.author_name, status: res.statusCode });
        } catch (e) {
          resolve({ ...v, title: data.slice(0, 100), status: res.statusCode });
        }
      });
    }).on('error', (err) => {
      resolve({ ...v, error: err.message });
    });
  });
}

async function run() {
  for (const v of vids) {
    const info = await fetchInfo(v);
    console.log(`[${info.tag}] ${info.id}`);
    console.log(`  Title: ${info.title}`);
    console.log(`  Author: ${info.author || ''}`);
  }
}

run();

