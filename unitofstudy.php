<?php
	if (!class_exists(UnitofStudy)) {
		class UnitofStudy {
			function insertUnits() {
				
				global $thdb;
				
				if (!empty($_POST)) {
					
					require_once 'db.php';
					
					$table = 'unitofstudy';
					
					$values = $thdb->clean($_POST);
					
					$uoscode = strtoupper($values['uoscode']);
					$uosname = strtoupper($values['uosname']);
					
					$fields = array('uoscode', 'uosname');
					
					$values = array(
							"uoscode"=>$uoscode,
							"uosname"=>$uosname);
					$sql = "SELECT * FROM ".$table." WHERE uoscode = '".$uoscode."'";
					$results = $thdb -> select($sql);
					
					if (mysql_num_rows($results) == 0) {
						$insert = $thdb->insert($link, $table, $fields, $values);
							
						if ($insert == true) {
							return "added";
						} else {
							return "no";
						}
					} else {
						return "exists";
					}
					
					
					
					
				}
			}
		}
	}
	
	$uos = new UnitofStudy();
?>