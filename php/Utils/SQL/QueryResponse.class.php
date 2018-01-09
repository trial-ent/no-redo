<?php
/**
 * Description of QueryResponse
 * 
 * Created on 06/09/2016, ~21:49:40
 * @author Matheus Leonardo dos Santos Martins
 * @copyright (c) 2016, TRIAL
 * 
 * @version 1.0
 * @package SQL
 */

/* 
 * 21/01/2017
 *      03:19:19 => renamed namespace from SQL to Utils\SQL
 *      19:40:50 => renamed namespace from Utils\SQL to NoRedo\Utils\SQL
 */

namespace NoRedo\Utils\SQL;

use NoRedo\Utils\Response;

class QueryResponse extends Response {
    
    private $statement;
    
    /* 15/09/2016, 20:56:10
     * Removed pass-by-reference in $bind argument
     */
    public function __construct(&$statement, $bind, $success) {
        $this->statement = $statement;
        parent::__construct($this->statement->execute($bind));
        if ($this->success()) {
            if ($success) {
                $this->setResult($success());
            }
        } else {
            $this->setError(new QueryError($this->statement->errorInfo()));
        }
    }
    
    public function existRows() {
        return $this->success() ? $this->statement->rowCount() > 0 : false;
    }

}