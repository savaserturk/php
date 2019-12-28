<?php 
public function administratorLogin($admin_username,$admin_password,$remember_me){
	try {
		$stmt=$this->db->prepare("SELECT * FROM admin WHERE admin_username=? AND admin_password=?");
		$stmt->execute([$admin_username,md5($admin_password)]);

		if (isset($_COOKIE['administratorLogin'])) {
			$stmt->execute([$admin_username,md5(openssl_decrypt($admin_password,"AES-128-ECB", "admin_coz"))]);
		}else{
			$stmt->execute([$admin_username,md5($admin_password)]);
		}

		if ($stmt->rowCount()==1) {

			$row=$stmt->fetch(PDO::FETCH_ASSOC);

			if ($row["admin_status"]==0) {
				return ['status'=>FALSE];
				exit;
			}

			$_SESSION['admin']=[
				"admin_username"=>$admin_username,
				"admin_lastname"=>$row['admin_lastname'],
				"admin_file"=>$row['admin_file'],
				"admin_title"=>$row['admin_title'],
				"admin_id"=>$row['admin_id']
			];


			if (!empty($remember_me) AND empty($_COOKIE['administratorLogin'])) {
				$admin=[
					"admin_username"=> $admin_username,
					"admin_password"=>openssl_encrypt($admin_password, "AES-128-ECB", "admin_coz")
				];
				setcookie("administratorLogin",json_encode($admin),strtotime("+30 day"),"/");

			}else if(empty($remember_me)){
				setcookie("administratorLogin",json_encode($admin),strtotime("-30 day"),"/");
			}

			
			return ["status" => TRUE];

		}else{

			return ["status"=> FALSE];
		}


	} catch (Exception $e) {
		return ['status'=>FALSE,'error'=>$e->getMessage()];
	}
}

?> 
