<?php
	require_once 'load.php';
	$uploaded = $user->uploadImage();
 	
?>

<html>
	<head>
		<title>Upload File</title>
		<style type="text/css">
			body { background: #c7c7c7;}
		</style>
	</head>

	<body>
		<div style="width: 960px; background: #fff; border: 1px solid #e4e4e4; padding: 20px; margin: 10px auto;">
			
			<?php if ( $uploaded == 1 ) : ?>
				<p style="background: #e49a9a; border: 1px solid #c05555; padding: 7px 10px;">
					No file selected.
				</p>
			<?php endif; ?>
			
			<?php if ( $uploaded == 2 ) : ?>
				<p style="background: #e49a9a; border: 1px solid #c05555; padding: 7px 10px;">
					Please choose JPEG, PNG or GIF.
				</p>
			<?php endif; ?>
			
			<?php if ( $uploaded == 3 ) : ?>
				<p style="background: #e49a9a; border: 1px solid #c05555; padding: 7px 10px;">
					Too large. Please limit the file size to 10MB.
				</p>
			<?php endif; ?>
			
			<h3>Upload Image</h3>
			
			<form action="upload.php" method="post" enctype ="multipart/form-data">
				<table>
					<tr>
						<td></td>
						<td><input type="file" name="image" /></td>
					</tr>
					<tr>
						<td>Filename</td>
						<td><input type="text" name="filename" /></td>
					</tr>
					<tr>
						<td></td>
						<td><input type="submit" name="upload" value="Upload Now" /></td>
					</tr>
				</table>
			</form>
		</div>
	</body>
</html>