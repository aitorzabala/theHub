<?php
	require_once('load.php');
	$user->login();
?>

<html>
	<head>
		<title>Login Form</title>
		<style type="text/css">
			body { background: #c7c7c7;}
		</style>
	</head>

	<body>
		<div style="width: 960px; background: #fff; border: 1px solid #e4e4e4; padding: 20px; margin: 10px auto;">
			
			<h3>Login</h3>
			
			<form action="login.php" method="post">
				<table>
					<tr>
						<td>Email:</td>
						<td><input type="text" name="email" /></td>
					</tr>
					<tr>
						<td>Password:</td>
						<td><input type="password" name="password" /></td>
					</tr>
					<tr>
						<td></td>
						<td><input type="submit" value="login" /></td>
					</tr>
				</table>
			</form>
			<p>Not a member? <a href="register.php">Register here</a></p>
		</div>
	</body>
</html>
