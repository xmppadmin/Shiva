function mark_as_spam(email_id) {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4 && xhttp.status == 200) {
          location.reload()
    } 
  }
  
  if (confirm("Mark email as spam?") == true) {
    xhttp.open("GET", "mark_as_spam?email_id=" + email_id , true);
    xhttp.send();
  }
}

function mark_as_phishing(email_id) {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4 && xhttp.status == 200) {
      location.reload()
    } 
  }
  
  if (confirm("Mark email as phishing?") == true) {
    xhttp.open("GET", "mark_as_phishing?email_id=" + email_id , true);
    xhttp.send();
  }
}

function delete_email(email_id) {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4 && xhttp.status == 200) {
      location.reload()
    } 
  }
  
  if (confirm("Permamently remove email from honeypot?") == true) {
    xhttp.open("GET", "delete_email?email_id=" + email_id , true);
    xhttp.send();
  }
}