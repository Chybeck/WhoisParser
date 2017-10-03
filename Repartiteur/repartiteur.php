<?php
namespace Novutec\WhoisParser;

class Repartiteur
{
	private $db_ip;
	private $db_login;
	private $db_pass;
	private $db_database;
	private $mysqli;
	public $server;
	public $source;
	
	
	  function __construct()
	  {
		 include_once("./config.inc.php");
		 $this->mysqli = new \mysqli($db_ip, $db_login, $db_pass, $db_database);
	  }
	  
	 
	
		
	/* 
	CREATE TABLE `whois_query` (
	  `id` int(11) NOT NULL,
	  `server` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
	  `source` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
	  `date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


	CREATE TABLE `whois_candidates` (
	  `id` int(11) NOT NULL,
	  `ip_source` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

	
	CREATE TABLE IF NOT EXISTS `whois_rate_limit` (
	  `id` int(11) NOT NULL,
	  `server` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
	  `whois_limit_amount` int(11) DEFAULT NULL,
	  `whois_limit_period` int(11) DEFAULT NULL,
	  `min_wait` int(11) DEFAULT NULL
	) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;	
	
	*/
	
	public function get_candidate_easy($server) 
	{
		// selection d'un candidat en prenant le dernier utilisé pour ce serveur de whois.
		$req = "	
		SELECT * 
		FROM `whois_candidates` c 
		LEFT JOIN (
		   SELECT source, MAX(Date) as date, server 
		   FROM whois_query 
		   WHERE server = '".$this->mysqli->real_escape_string($server)."'
		   GROUP BY source 
		) q ON q.source = c.ip_source
		WHERE (date < NOW() OR date IS NULL) AND active = true
		ORDER BY date ASC
		LIMIT 1
		";
		//print_r($req);
		$sql = $this->mysqli->query($req);
		if (!$sql) return null;
		if (($candidate = $sql->fetch_object()) !== null)
			return $candidate->ip_source;
		else return null;
	}
	
	public function log_query($source, $server)
	{
			$req = "INSERT into `whois_query` (source, server) VALUES ('".$this->mysqli->real_escape_string($source)."', '".$this->mysqli->real_escape_string($server)."')";
			return $this->mysqli->query($req);
	}
	

	public function action_suite_erreur ($source, $server, $bl_time = 10)
	{
		$server = $this->mysqli->real_escape_string($server);
		$source = $this->mysqli->real_escape_string($source);
		// on va insérer un query correspondant à une date dans le futur de sorte à exclure cette source.
		$req = "INSERT INTO whois_query (server, source, date) VALUES ('$server', '$source', NOW() + INTERVAL $bl_time MINUTE)";
		//print_r($req);
		return $this->mysqli->query($req);
	}


	
	
	function get_candidate($server) 
	{
		// selection d'un pool de sources candidates en triant par dernier candidat utilisé.
		$req = "
		SELECT * 
		FROM `whois_candidates` c 
		LEFT JOIN (
		   SELECT source, MAX(Date) as date, server 
		   FROM whois_query 
		   WHERE server = '".$this->mysqli->real_escape_string($server)."'
		   GROUP BY source 
		) q ON q.source = c.ip_source
		WHERE (date < NOW() OR date IS NULL) AND active = true
		ORDER BY date ASC
		";
		if (($pool = $this->mysqli->query($req)) === false) return null;
		

		
		// selection des regles associés au serveur de whois
		$req = "SELECT * from whois_rate_limit WHERE server = '".$this->mysqli->real_escape_string($server)."'";
		//print_r($req.PHP_EOL);
		$rules = $this->mysqli->query($req);
		if (($rule = $rules->fetch_object()) != null)
		{		
			// vérification des rules pour chaque candidat. On sort dès qu'on en trouve un bon.
			while ($candidate = $pool->fetch_object()) {
				

				// etape 1 : on vérifie que pour ce candidat on a pas fait moins de whois_limit_amount dans la période de temps de whois_limit_period
				if ($rule->whois_limit_amount !== null && $rule->whois_limit_period !== null)
				{
					// TODO : Ajouter ça.. si tant est que ce soit utile et pas redondant avec l'étape 2.
					// si ca va pas continue;
				}
				// etape 2 : on vérifie que le dernier appel de ce candidat est inférieur a min_wait
				if ($rule->min_wait !== null)
				{
					$tmp_date = (time() - strtotime($candidate->date));
					if ($tmp_date <= $rule->min_wait);
					// si ca va pas continue;
				}
				
				// on a passé les règles on output cette ip candidate !
				return $candidate->ip_source;
			}
			return null;
		}
		else
		{
			$candidate = $pool->fetch_object(); // on ne prend que le dernier.
			if (isset($candidate->ip_source))
			  return $candidate->ip_source;
                        else return null;
		}
		
	}
}






/*




*/
?>
