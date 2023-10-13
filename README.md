# login
<?php
	$response = array();
	session_start();

	if (isset($_POST["action"]) && $_POST["action"] == "userLogin") {
		$username = htmlspecialchars($_POST["username"]);
		$password = htmlspecialchars($_POST["password"]);
		userLogin($username, $password);
		
	}
	if (isset($_POST["action"]) && $_POST["action"] == "registerUser") {
		$username = htmlspecialchars($_POST["username"]);
		$password = htmlspecialchars($_POST["password"]);
		registerUser($username, $password);
		
	}
	if (isset($_POST["action"]) && $_POST["action"] == "getAddress") {
		getAddress();
		
	}
	
	function registerUser($username, $password)
	{
		include 'config.php';
		GLOBAL $response;
		$pass_hash = password_hash($password, PASSWORD_BCRYPT, ["COST"=>8]);
		$stmt = $con->prepare("INSERT INTO `usercredentials`(`username`, `password`) VALUES (?, ?)");
		$stmt->bind_param("ss", $username, $pass_hash);

		if ($stmt->execute()) {
			$response['message'] = "User registered successfully";
			$response['status'] = "success";
			

		}else{
			
			$response['message'] = "Username exists on the system. Try again with different username.";
			$response['status'] = "failed";

		}
	}

	function userLogin($username, $password){
		include 'config.php';
		GLOBAL $response;

		$sql = $con->prepare("select id, username, password from usercredentials where username = ? limit 1");
        $sql->bind_param("s", $username);
        $sql->execute();

        $result = $sql->get_result();
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();

            $getid = $row["id"];
          	$username = $row["username"];
          	$getpassword = $row["password"];

          	if (password_verify($password, $getpassword)) {
          		$sql_profile = $con->prepare("select id, address1, state from clientinformation where userid = ?");
		        $sql_profile->bind_param("s", $getid);
		        $sql_profile->execute();

		        $result_profile = $sql_profile->get_result();
		        if ($result_profile->num_rows > 0) {
		        	$row_profile = $result_profile->fetch_assoc();
		        	$response['message'] = "success";
	          		$response['id'] = $getid;
		            $response['username'] = $username;
		            $response['profile'] = "true";

		            $_SESSION['id'] = $getid;
		            $_SESSION['username'] = $username;
		            $_SESSION['address'] = $row_profile["address1"];
		            $_SESSION['state'] = $row_profile["state"];
		        }else{
		        	$response['message'] = "success";
	          		$response['id'] = $getid;
		            $response['username'] = $username;
		            $response['profile'] = "false";

		            $_SESSION['id'] = $getid;
		            $_SESSION['username'] = $username;

		        }

          		

          	}else{
          		$response['message'] = "failed";
          	}
          	
        }else{
        	$response['message'] = "failed";
        }
    }
    function getAddress()
	{
		GLOBAL $response;
		$response['address'] = $_SESSION['address'];

	}
    echo json_encode($response);


?>
