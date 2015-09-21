<?php
	require_once('load.php');
	
	function loadLanguages(){
		global $conn;
		$sql = 'SELECT english_name FROM languages WHERE 1';

		$stm = $conn->prepare($sql);

		$stm->execute();
		$data = $stm->fetchAll();

		return $data;
	}
	$user -> setLanguage();	
?>
<!DOCTYPE html>
<html>

	<body>


		<b>Insert Language Preference Of User</b>
		<br>

		<form action = "language.php" method = "POST">

			<input type = "text" name = "userId">
			<input type = "search" list = "Languages" name = "pref_language"> 
		<?
			//	Insert all languages retreived to a <datalist> element

			$data = loadLanguages();

			echo '<datalist id= "Languages">';
			for ($i=0; $i < count($data); $i++) { 
				echo '<option value = "' . $data[$i][0] . '">';
			}
			echo "</datalist>";
		?>
			<input type = "submit">
		</form>
		<br><br>

		<b>Retreive Language Preference Of User</b>
		<br>

		<form action = "language.php" method = "POST">

			<input type = "text" name = "userId">
			<input type = "hidden" name = "searchUserLang" value = "1">

			<input type = "submit">
		</form>
		<?
			$data = $user -> getLanguage();
			if (!empty($data) && !empty($data["userId"]) && !empty($data["languages"])) {
				echo "<b>UserId:".$data["userId"]."<b><br>";
				echo '<table>';
				$c = 1;
				for ($i=0; $i < count($data["languages"]); $i++) { 
					echo "<tr><td>>".$c++."</td><td>".$data["languages"][$i]["2letter"]."</td></tr>";
				}
				echo "</table>";

			}
		?>
	</body>
</html>
