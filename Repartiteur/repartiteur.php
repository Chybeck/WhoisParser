<?php
namespace Novutec\WhoisParser;

class Repartiteur
{
	private $mysqli;
	public $server;
	public $source;

	  function __construct()
	  {
		 $this->mysqli = new \mysqli("127.0.0.1", "root", "qx2xcka", "repartiteur");
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
		WHERE date < NOW() OR date IS NULL
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
	

	public function action_suite_erreur ($source, $server)
	{
		$server = $this->mysqli->real_escape_string($server);
		$source = $this->mysqli->real_escape_string($source);
		// on va insérer un query correspondant à une date dans le futur de sorte à exclure cette source.
		$req = "INSERT INTO whois_query (server, source, date) VALUES ('$server', '$source', NOW() + INTERVAL 10 MINUTE)";
		//print_r($req);
		return $this->mysqli->query($req);
	}

}






/*


function get_candidate($server) 
{
    // selection d'un pool de sources candidates en triant par dernier candidat utilisé.
    $req = "
    select c.*, q.server, q.date FROM whois_candidates c LEFT JOIN whois_query q ON c.ip_source = q.source
    WHERE 
    q.id = (
        SELECT max(id)
        FROM whois_query
        WHERE source = q.source AND server = ".$mysqli->real_escape_string($server)."
    )
    ORDER BY date ASC;
    ";
    $pool = mysqli->query($req);
    

    
    // selection des regles associés au serveur de whois
    $req = "SELECT * from whois_rate_limit WHERE whois_server = ".$mysqli->real_escape_string($server);
    $rules = mysqli->query($req);
    $rule = $rules->fetch_object();
    
    // vérification des rules pour chaque candidat. On sort dès qu'on en trouve un bon.
    while ($candidate = $pool->fetch_object()) {

        // etape 1 : on vérifie que pour ce candidat on a pas fait moins de whois_limit_amount dans la période de temps de whois_limit_period
        
        // etape 2 : on vérifie que le dernier appel de ce candidat est inférieur a min_wait
        
        
        return $candidate->ip_source;
    }
    
    return null;
}

*/
?>
