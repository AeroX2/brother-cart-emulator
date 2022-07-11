const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML>
<html lang="en">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta charset="UTF-8">
</head>
<body>
  <p id="serverStatus">Polling server...</p>
  <p id="status"></p>
  <button onclick="writeImage()">Write image</button>
  <h3>Upload File<h3>
  <form id="upload_form" enctype="multipart/form-data" method="post">
    <input type="file" name="file1" id="file1" onchange="uploadFile()"><br>
    <progress id="progressBar" value="0" max="100" style="width:300px;"></progress>
    <h3 id="status"></h3>
    <p id="loadedTotal"></p>
  </form>
<script>

function _(el) {
  return document.getElementById(el);
}
function writeImage() {
  xmlhttp=new XMLHttpRequest();
  xmlhttp.open("POST", "/write", false);
  xmlhttp.send();
}
function uploadFile() {
  var file = _("file1").files[0];
  // alert(file.name+" | "+file.size+" | "+file.type);
  var formdata = new FormData();
  formdata.append("file1", file);
  var ajax = new XMLHttpRequest();
  ajax.upload.addEventListener("progress", progressHandler, false);
  ajax.addEventListener("error", errorHandler, false);
  ajax.addEventListener("abort", abortHandler, false);
  ajax.open("POST", "/");
  ajax.send(formdata);
}
function progressHandler(event) {
  _("loadedTotal").innerText = "Uploaded " + event.loaded + " bytes";
  var percent = (event.loaded / event.total) * 100;
  _("progressBar").value = Math.round(percent);
  _("status").innerText = Math.round(percent) + "% uploaded... please wait";
  if (percent >= 100) {
    _("status").innerText = "Please wait, writing file to chip";
  }
}
function errorHandler(event) {
  _("status").innerText = "Upload Failed";
}
function abortHandler(event) {
  _("status").innerText = "Upload Aborted";
}
function onStatusLoad() {
  _("serverStatus").innerText = this.responseText;
}
function onStatusError() {
  _("serverStatus").innerText = "Can't contact server is it down?";
}
function pollServer() {
  var request = new XMLHttpRequest();
  request.addEventListener("load", onStatusLoad);
  request.addEventListener("error", onStatusError);
  request.open("GET", "/status");
  request.send();
  setTimeout(pollServer,1000);
}
pollServer();
</script>
</body>
</html>
)rawliteral";