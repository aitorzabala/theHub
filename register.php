<?php
 	require_once 'load.php';
	$user -> register();
?>

<html>
	<head>
		<title>Registration Form</title>
		<style type="text/css">
			body { background: #c7c7c7;}
		</style>
	</head>

	<body>
		<div style="width: 960px; background: #fff; border: 1px solid #e4e4e4; padding: 20px; margin: 10px auto;">
			<h3>Register</h3>
			
			<form action="register.php" method="post">
				<table>
					<tr>
						<td>First Name:</td>
						<td><input type="text" name="firstName" /></td>
					</tr>
					<tr>
						<td>Last Name:</td>
						<td><input type="text" name="lastName" /></td>
					</tr>
					<tr>
						<td>Email:</td>
						<td><input type="text" name="email" /></td>
					</tr>
					<tr>
						<td>Password:</td>
						<td><input type="password" name="password" /></td>
					</tr>
					<tr>
						<td>Type:</td>
						<td>
							<select name="type">
								<option value = "S">Student</option>
								<option value = "T">Tutor</option>
							</select>
						</td>
					</tr>
					
					<input type="hidden" name="registeredOn" value="<?php echo time(); ?>" />
					<tr>
						<td></td>
						<td><input type="submit" value="Register" /></td>
					</tr>
				</table>
			</form>
			<p>Already a member? <a href="login.php">Log in here</a></p>
		</div>
	</body>
</html>
