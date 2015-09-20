<?php
	require_once 'loaduos.php';
	$added = $uos->insertUnits()
?>

<html>
	<head>
		<title>Add Unit of Study</title>
		<style type="text/css">
			body { background: #c7c7c7;}
		</style>
	</head>

	<body>
		<div style="width: 960px; background: #fff; border: 1px solid #e4e4e4; padding: 20px; margin: 10px auto;">
			<?php if ( $added == "added" ) : ?>
				<p style="background: #fef1b5; border: 1px solid #eedc82; padding: 7px 10px;">
					The data has been added.
				</p>
			<?php endif; ?>
			<?php if ( $added == "no" ) : ?>
				<p style="background: #e49a9a; border: 1px solid #c05555; padding: 7px 10px;">
					There was an error adding the data. Please try again.
				</p>
			<?php endif; ?>
			<?php if ( $added == "exists" ) : ?>
				<p style="background: #e49a9a; border: 1px solid #c05555; padding: 7px 10px;">
					The course already exists.
				</p>
			<?php endif; ?>
			<h3>Add Unit of Study</h3>
			
			<form action="addUOS.php" method="post">
				<table>
					<tr>
						<td>Uos Code:</td>
						<td><input type="text" name="uoscode" /></td>
					</tr>
					<tr>
						<td>Uos Name:</td>
						<td><input type="text" name="uosname" /></td>
					</tr>
					<tr>
						<td></td>
						<td><input type="submit" value="Insert" /></td>
					</tr>
				</table>
			</form>
		</div>
	</body>
</html>