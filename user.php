<?php

if(!class_exists(User)) {
	class User {
		
		function register() {
			
			global $thdb;
			
			//Check to make sure the form submission is coming from our script
			//The full URL of our registration page
			$current = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
			
			//The full URL of the page the form was submitted from
			$referrer = $_SERVER['HTTP_REFERER'];
			
			/*
			 * Check to see if the $_POST array has date (i.e. our form was submitted) and if so,
			 * process the form data.
			 */
			if (!empty($_POST)) {
				
				/*
				 * Here we actually run the check to see if the form was submitted from our
				 * site. Since our registration from submits to itself, this is pretty easy. If
				 * the form submission didn't come from the register.php page on our server,
				 * we don't allow the data through. Good for webapps. Need to see what I can do mobile apps.
				 */
// 				if ($referrer == $current) {
					
				require_once 'db.php';
				
				global $conn;
				//Set up the variables we'll need to pass to our insert method
				//This is the name of the table we want to insert data into
				$table = 'users';
					
				//These are the fields in that table that we want to insert data into
				$fields = array('userId', 'firstName', 'lastName', 'email', 'password', 'type', 'registeredOn');
				
				//These are the values from our registration form... cleaned using our clean method
				$values = $thdb->clean($_POST);
				
				//Now, we're breaking apart our $_POST array, so we can store our password securely
				$userId = '';
				$firstName = $_POST['firstName'];
				$lastName = $_POST['lastName'];
				$email = $_POST['email'];
				$password = $_POST['password'];
				$type = $_POST['type'];
				$registeredOn = $_POST['registeredOn'];
				
				$response = $this->doesUserExist($email);
				
				if ($response['exists']) {
					$meta = new BasicResponse();
					$meta->success = false;
					$meta->message = "This email already exists.";
					die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
				}
				
				//We create a NONCE using the action, username, timestamp, and the NONCE SALT
				$nonce = md5('registration-' . $email . $registeredOn . NONCE_SALT);
				
				//We hash our password
				$password = $thdb->hash_password($password, $nonce);
				
				$query = $conn->prepare("INSERT INTO ".$table." (userId, firstName, lastName, email, password, type, registeredOn) VALUES (:id, :fname, :lname, 
						:email, :pwd, :type, :regon)");
				
				$query->bindParam(":id", $userId);
				$query->bindParam(":fname", $firstName);
				$query->bindParam(":lname", $lastName);
				$query->bindParam(":email", $email);
				$query->bindParam(":pwd", $password);
				$query->bindParam(":type", $type);
				$query->bindParam(":regon", $registeredOn);
				
				$success = $query->execute();
				
				if ($success) {
					//change to json if not changed
					$meta = new BasicResponse();
					$meta->success = true;
					$meta->message = "Registration successful";
					
					$userId = $conn->lastInsertId();
					$image = new ImageResponse();
					$image->imageName = null;
					$image->imageUrl = null;
					$details = new UserResponse();
					$details->userId = $userId;
					$details->firstName = $firstName;
					$details->lastName = $lastName;
					$details->email = $email;
					$details->type = $type;
					$details->image = $image;
					
					die(json_encode(array("meta" => $meta,"details" => $details), JSON_NUMERIC_CHECK));
				} else {
					$meta = new BasicResponse();
					$meta->success = true;
					$meta->message = "Error in registartion. Please try again later.";
					die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
				}
				
// 				}
// 				else {
					
// // 					change to json if not changed
// 					$meta = new BasicResponse();
// 					$meta->success = false;
// 					$meta->message = 'Your form submission did not come from the correct page. Please check with the site administrator.';
// 					die(json_encode(array("meta"=>$meta)));
// 					die('Your form submission did not come from the correct page. Please check with the site administrator. Referrer = ' . $referrer 
// 							. 'current = ' . $current);
				
// 				}
				
			}
			
		}
		
		function login() {
			
			global $thdb;
			
			global $conn;
			
			if (!empty($_POST)) {
				
				// Clean our form data 
				$values = $thdb->clean($_POST);
				
				// Email and password submitted by the user
				$sub_email = $values['email'];
				$sub_password = $values['password'];
				
				// The name of the table being used
				$table = 'users LEFT OUTER JOIN images USING(userId)';
				
				$response = $this->doesUserExist($sub_email);
				
				if (!$response['exists']) {
					//Change this to json if not chamged
					$meta = new BasicResponse();
					$meta->success = false;
					$meta->message = "Sorry. This email id does not exist.";
					die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
				}
				
				$stmt = $response['stmt'];
				
				$result = $stmt->fetch(PDO::FETCH_ASSOC);
				
				//Get the registration date of the user
				$sto_registeredOn = $result['registeredOn'];
				
				//The hashed password of the user
				$sto_password = $result['password'];
				
				//Recreate our NONCE used at registration
				$nonce = md5('registration-' . $sub_email . $sto_registeredOn . NONCE_SALT);
				
				//Rehash the submitted password to see if it matches the stored hash
				$sub_password = $thdb -> hash_password($sub_password, $nonce);
				
				//Check to see if the submitted password matches the stored password
				if ($sub_password == $sto_password) {
					
					//If there's a match, we rehash password to store in a cookie
					$authnonce = md5('cookie-' . $sub_email . $sto_registeredOn . AUTH_SALT);
					$authID = $thdb -> hash_password($sub_password, $authnonce);
					
					//Set our authorization cookie
					setcookie('theHub[user]', $sub_email, 0, '', '', '', true);
					setcookie('theHub[authID]', $authID, 0, '', '', '', true);
					
					$sto_userId = $result['userId'];
					$sto_firstName = $result['firstName'];
					$sto_lastName = $result['lastName'];
					$sto_email = $result['email'];
					$sto_type = $result['type'];
					
					$meta = new BasicResponse();
					$meta->success = true;
					$meta->message = "You have logged in successfully.";
					
					$image = new ImageResponse();
					$image->imageName = $result['imageName'];
					$image->imageUrl = $result['imageUrl'];
					
					
					$details = new UserResponse();
					$details->userId = $sto_userId;
					$details->firstName = $sto_firstName;
					$details->lastName = $sto_lastName;
					$details->email = $sto_email;
					$details->type = $sto_type;
					$details->image = $image;
					
					die(json_encode(array("meta"=>$meta, "details"=>$details), JSON_NUMERIC_CHECK));
					
				} else {
					
					$meta = new BasicResponse();
					$meta->success = false;
					$meta->message = "Email/Password do not match. Please try again";
					die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
					
				}
				
			}
			
		}
		
		function logout() {
			//Expire our auth coookie to log the user out
			$idout = setcookie('theHub[authID]', '', -3600, '', '', '', true);
			$userout = setcookie('theHub[user]', '', -3600, '', '', '', true);
				
			if ( $idout == true && $userout == true ) {
				$meta = new BasicResponse();
				$meta->success = true;
				$meta->message = 'Logged out successfully';
				die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
			} else {
				$meta = new BasicResponse();
				$meta->success = false;
				$meta->message = 'Unable to logout. Please try again';
				die(json_encode(array("meta"=>$meta)));
			}
		}
			
		function checkLogin() {
			global $thdb;
		
			//Grab our authorization cookie array
			$cookie = $_COOKIE['theHub'];
				
			//Set our user and authID variables
			$user = $cookie['user'];
			$authID = $cookie['authID'];
				
			/*
			 * If the cookie values are empty, we redirect to login right away;
			 * otherwise, we run the login check.
			*/
			if ( !empty ( $cookie ) ) {
		
				//Query the database for the selected user
				$table = 'users';
				$sql = "SELECT * FROM $table WHERE email = '" . $user . "'";
				$results = $thdb->select($sql);
		
				//Kill the script if the submitted username doesn't exit
				if (!$results) {
					die('Sorry, that username does not exist!');
				}
		
				//Fetch our results into an associative array
				$results = mysql_fetch_assoc( $results );
		
				//The registration date of the stored matching user
				$sto_reg = $results['registeredOn'];
		
				//The hashed password of the stored matching user
				$sto_pass = $results['password'];
		
				//Rehash password to see if it matches the value stored in the cookie
				$authnonce = md5('cookie-' . $user . $sto_reg . AUTH_SALT);
				$sto_pass = $thdb->hash_password($sto_pass, $authnonce);
		
				if ( $sto_pass == $authID ) {
					$meta = new BasicResponse();
					$meta->success = true;
					$meta->message = 'logged in.';
					die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
				} else {
					$meta = new BasicResponse();
					$meta->success = false;
					$meta->message = 'Not logged in.';
					die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
				}
			} else {
				$meta = new BasicResponse();
				$meta->success = false;
				$meta->message = 'Not logged in.';
				die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
			}
				
		}
		
		function doesUserExist($sub_email) {
			global $conn;
			
			$table = "users LEFT OUTER JOIN images USING(userId)";
			/*
			 * Run our query to get all data from the users table where the user
			 * login matches the submitted login.
			 */
			$stmt  = $conn->prepare("SELECT * FROM $table WHERE email = " . $conn->quote($sub_email)) ;
			$stmt->execute();
			
			$rows = $stmt->rowCount();
			
			//Kill the script if the submitted username doesn't exit
			if ($rows == 0) {
					
				return array("exists"=>false, "stmt"=>$stmt);
					
			} else {
				
				return array("exists"=>true, "stmt"=>$stmt);
				
			}
		}
		
		function uploadImage() {
					
			global $thdb;
			
			global $conn;
			
			$maxFileSize = 10000000;
			
			$file = $_FILES['image']['tmp_name'];
			
			$imageTmpName = addslashes($_FILES['image']['tmp_name']);
			$imageName = $_FILES['image']['name'];
			if ($imageName == '') {
				return 1;
			}
			$imageData = getimagesize($_FILES['image']['tmp_name']);
			$imageFileSize = $_FILES['image']['size'];
			
			if ($imageData == FALSE ||
					!($imageData[2] == IMAGETYPE_GIF || $imageData[2] == IMAGETYPE_JPEG
							|| $imageData[2] == IMAGETYPE_PNG)) {
				return 2;
			}
			
			if ($imageFileSize > $maxFileSize) {
				return 3;
			}
			
			$userid = $_POST['userId'];
			$tmp = explode(".", $imageName);
			$ext = $tmp[count($tmp) - 1];
			$newName = $userid."as".round(microtime(true))."";
			$newNameExt = $newName.".".$ext;
			
			move_uploaded_file($imageTmpName, "images/$newNameExt");
			$table = 'images';
			try {
				$query = $conn->prepare("INSERT INTO " .$table." (imageName,imageUrl,userId) VALUES (?,?,?)");
				
				$success = $query->execute(array($newName,"theHub/images/".$newNameExt, $userid));
			} catch (PDOException $e) {
				echo $e->getMessage();
			}
			
			if($success) {
				try {
					
					$stmt = $conn->prepare("SELECT * FROM users LEFT OUTER JOIN $table USING (userId) WHERE userId = ?");
					$stmt->execute(array($userid));
					
					$result = $stmt->fetch(PDO::FETCH_ASSOC);
					
					$meta = new BasicResponse();
					$meta->success = true;
					$meta->message = "Image uploaded";
					
					
					$image = new ImageResponse();
					$image->imageName = $result['imageName'];
					$image->imageUrl = $result['imageUrl'];
					
					$details = new UserResponse();
					$details->userId = $result['userId'];
					$details->firstName = $result['filename'];
					$details->lastName = $result['lastName'];
					$details->email = $result['email'];
					$details->type = $result['type'];
					$details->image = $image;
					
					die(json_encode(array("meta"=>$meta, "details"=>$details), JSON_NUMERIC_CHECK));
					
				} catch (Exception $e) {
					
					echo $e->getMessage();
					
				}
				
				
				
			} else {
				$meta = new BasicResponse();
				$meta->success = false;
				$meta->message = "There was an error uploading the image. Please try again";
				
				die(json_encode(array("meta"=>$meta), JSON_NUMERIC_CHECK));
			}
						
		
		}
		
	}
	
	
	
	
}

//Instantiate the User class
$user = new User();

?>