#!/usr/bin/env node

var http=require('http');
var fs=require('fs');
var url=require('url');
var mime = require('mime');
var program = require('commander');
var path=require('path');
var pkg = require( path.join(__dirname, 'package.json') );

program
    .version(pkg.version)
    .option('-p, --port <port>', 'Port on which to listen to (defaults to 8080)', parseInt)
    .parse(process.argv);

var port = program.port || 8080;

var server=http.createServer(function(req,resp)
{
  console.log(req.connection.remoteAddress,req.url, "["+(new Date()).toLocaleString()+"]");
  var myurl=url.parse(req.url);
  if(myurl.pathname=="/")
  {
    myurl.pathname="/index.html";
  }
//  console.log(myurl);
  fs.readFile(path.join(process.cwd(),myurl.pathname),function(err,data)
  {
    setContentType(myurl.pathname,resp);
    resp.setHeader("Access-Control-Allow-Origin","*");
    resp.end(data);
  });
});
server.listen(port);

function setContentType(file,resp)
{
  resp.setHeader("Content-type",mime.lookup(path.join(process.cwd(),file)));
}
