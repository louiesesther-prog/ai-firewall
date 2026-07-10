alert("Test extension loaded!");
console.log("Test extension started");

var div = document.createElement('div');
div.style.cssText = 'position:fixed;top:0;left:0;background:#22c55e;padding:10px;color:white;z-index:999999;font-size:14px';
div.textContent = 'TEST EXTENSION: LOADED!';
document.body.appendChild(div);