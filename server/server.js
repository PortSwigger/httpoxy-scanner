var http = require('http');

const PORT = 8000;

console.log(`Serving on http://localhost:${PORT}, press ctrl+c to stop`);
http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/html'});

  if (req.headers["proxy"] !== undefined) {
    http.get(req.headers["proxy"]);
    console.log(`Making request to: ${req.headers["proxy"]}`);
    res.end(`Making request to: ${req.headers["proxy"]}`);
  } else {
    res.end(`
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
    <title>Demo</title>
</head>
<body>
  Send a Proxy header.
</body>
</html>
    `);
  }
}).listen(PORT, 'localhost');
