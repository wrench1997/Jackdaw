
const HTA = require('html-to-ast')


var html = `<!DOCTYPE html>

<html lang="en-GB">

	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

		<title>Welcome :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>

		<link rel="stylesheet" type="text/css" href="dvwa/css/main.css" />

		<link rel="icon" type="\image/ico" href="favicon.ico" />

		<script type="text/javascript" src="dvwa/js/dvwaPage.js"></script>

	</head>

	<body class="home">
		<div id="container">

			<div id="header">

				<img src="dvwa/images/logo.png" alt="Damn Vulnerable Web Application" />

			</div>

			<div id="main_menu">

				<div id="main_menu_padded">
				<ul class="menuBlocks"><li class="selected"><a href=".">Home</a></li>
<li class=""><a href="instructions.php">Instructions</a></li>
<li class=""><a href="setup.php">Setup / Reset DB</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="vulnerabilities/brute/">Brute Force</a></li>
<li class=""><a href="vulnerabilities/exec/">Command Injection</a></li>
<li class=""><a href="vulnerabilities/csrf/">CSRF</a></li>
<li class=""><a href="vulnerabilities/fi/.?page=include.php">File Inclusion</a></li>
<li class=""><a href="vulnerabilities/upload/">File Upload</a></li>
<li class=""><a href="vulnerabilities/captcha/">Insecure CAPTCHA</a></li>
<li class=""><a href="vulnerabilities/sqli/">SQL Injection</a></li>
<li class=""><a href="vulnerabilities/sqli_blind/">SQL Injection (Blind)</a></li>
<li class=""><a href="vulnerabilities/weak_id/">Weak Session IDs</a></li>
<li class=""><a href="vulnerabilities/xss_d/">XSS (DOM)</a></li>
<li class=""><a href="vulnerabilities/xss_r/">XSS (Reflected)</a></li>
<li class=""><a href="vulnerabilities/xss_s/">XSS (Stored)</a></li>
<li class=""><a href="vulnerabilities/csp/">CSP Bypass</a></li>
<li class=""><a href="vulnerabilities/javascript/">JavaScript</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="security.php">DVWA Security</a></li>
<li class=""><a href="phpinfo.php">PHP Info</a></li>
<li class=""><a href="about.php">About</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="logout.php">Logout</a></li>
</ul>
				</div>

			</div>

			<div id="main_body">

				
<div class="body_padded">
	<h1>Welcome to Damn Vulnerable Web Application!</h1>
	<p>Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students & teachers to learn about web application security in a controlled class room environment.</p>
	<p>The aim of DVWA is to <em>practice some of the most common web vulnerabilities</em>, with <em>various levels of difficultly</em>, with a simple straightforward interface.</p>
	<hr />
	<br />

	<h2>General Instructions</h2>
	<p>It is up to the user how they approach DVWA. Either by working through every module at a fixed level, or selecting any module and working up to reach the highest level they can before moving onto the next one. There is not a fixed object to complete a module; however users should feel that they have successfully exploited the system as best as they possible could by using that particular vulnerability.</p>
	<p>Please note, there are <em>both documented and undocumented vulnerability</em> with this software. This is intentional. You are encouraged to try and discover as many issues as possible.</p>
	<p>DVWA also includes a Web Application Firewall (WAF), PHPIDS, which can be enabled at any stage to further increase the difficulty. This will demonstrate how adding another layer of security may block certain malicious actions. Note, there are also various public methods at bypassing these protections (so this can be seen as an extension for more advanced users)!</p>
	<p>There is a help button at the bottom of each page, which allows you to view hints & tips for that vulnerability. There are also additional links for further background reading, which relates to that security issue.</p>
	<hr />
	<br />

	<h2>WARNING!</h2>
	<p>Damn Vulnerable Web Application is damn vulnerable! <em>Do not upload it to your hosting provider's public html folder or any Internet facing servers</em>, as they will be compromised. It is recommend using a virtual machine (such as <a href="https://www.virtualbox.org/" target="_blank">VirtualBox</a> or <a href="https://www.vmware.com/" target="_blank">VMware</a>), which is set to NAT networking mode. Inside a guest machine, you can download and install <a href="https://www.apachefriends.org/" target="_blank">XAMPP</a> for the web server and database.</p>
	<br />
	<h3>Disclaimer</h3>
	<p>We do not take responsibility for the way in which any one uses this application (DVWA). We have made the purposes of the application clear and it should not be used maliciously. We have given warnings and taken measures to prevent users from installing DVWA on to live web servers. If your web server is compromised via an installation of DVWA it is not our responsibility it is the responsibility of the person/s who uploaded and installed it.</p>
	<hr />
	<br />

	<h2>More Training Resources</h2>
	<p>DVWA aims to cover the most commonly seen vulnerabilities found in today's web applications. However there are plenty of other issues with web applications. Should you wish to explore any additional attack vectors, or want more difficult challenges, you may wish to look into the following other projects:</p>
	<ul>
		<li><a href="https://github.com/webpwnized/mutillidae" target="_blank">Mutillidae</a></li>
		<li><a href="https://owasp.org/www-project-broken-web-applications/migrated_content" target="_blank">OWASP Broken Web Applications Project
</a></li>
	</ul>
	<hr />
	<br />
</div>
				<br /><br />
				

			</div>

			<div class="clear">
			</div>

			<div id="system_info">
				<div align="left"><em>Username:</em> admin<br /><em>Security Level:</em> impossible<br /><em>Locale:</em> en<br /><em>PHPIDS:</em> disabled<br /><em>SQLi DB:</em> mysql</div>
			</div>

			<div id="footer">

				<p>Damn Vulnerable Web Application (DVWA) v1.10 *Development*</p>
				<script src='/dvwa/js/add_event_listeners.js'></script>

			</div>

		</div>

	</body>

</html>`


// becomes this AST:
const ast = HTA.parse(html);

console.log(JSON.stringify(ast));
const fs = require('fs')
const content = JSON.stringify(ast)
const opt = {
    flag: 'w+', // a：追加写入；w：覆盖写入
}

fs.writeFile('test.txt', content, opt, (err) => {
    if (err) {
        console.error(err)
    }
})
